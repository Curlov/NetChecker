"""Exercise ASGI directly, without starting a server or making network calls."""
import asyncio
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

import schema
import database
from web.main import app


async def asgi_request(method, url, headers=(), body=None):
    parsed = urlsplit(url)
    events = []
    request_sent = False
    request_body = json.dumps(body).encode() if body is not None else b''
    request_headers = list(headers)
    if body is not None:
        request_headers.append((b'content-type', b'application/json'))

    async def receive():
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {'type':'http.request','body':request_body,'more_body':False}
        await asyncio.Event().wait()

    async def send(message):
        events.append(message)

    await app({'type':'http','asgi':{'version':'3.0','spec_version':'2.4'},'http_version':'1.1',
        'method':method,'scheme':'http','path':parsed.path,'raw_path':parsed.path.encode(),
        'query_string':parsed.query.encode(),'root_path':'','headers':request_headers,
        'server':('synthetic',8000),'client':('synthetic',1)},receive,send)
    status = next(event['status'] for event in events if event['type']=='http.response.start')
    body = b''.join(event.get('body',b'') for event in events if event['type']=='http.response.body')
    return status, body


async def asgi_get(url, headers=()):
    return await asgi_request('GET', url, headers)


class WebTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name)/'inventory.db'
        connection = sqlite3.connect(self.path); connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA foreign_keys=ON'); schema.initialize_database(connection)
        self.network = database.save_network(connection,'192.0.2.0/24','test0',None)
        connection.execute("INSERT INTO network_scopes(id,name,customer,site) VALUES(2,'test2','private2','site')")
        connection.commit()
        self.other_network = database.save_network(connection,'192.0.2.0/24','test0',None,scope_id=2)
        self.ids = []
        for network,ip,mac in [(self.network,'192.0.2.10','00:11:22:33:44:55'),
                              (self.network,'192.0.2.2','00:11:22:33:44:66'),
                              (self.other_network,'192.0.2.10','00:11:22:33:44:55')]:
            run = database.start_scan_run(connection,network,'discovery')
            self.ids.append(database.save_discovery_host(connection,network,run,{'ip':ip,'mac':mac}))
            database.finish_scan_run(connection,run)
        self.snapshots = []
        for network,status in [(self.network,'complete'),(self.network,'complete'),(self.other_network,'complete'),(self.network,'running')]:
            cursor = connection.execute('INSERT INTO topology_snapshots(network_id,interface,status) VALUES(?,?,?)',(network,'test0',status))
            self.snapshots.append(cursor.lastrowid)
        connection.commit(); connection.close()
        self.stack = ExitStack()
        self.stack.enter_context(patch('web.database.DB_PATH',self.path))
        self.stack.enter_context(patch.dict(os.environ,{'NETCHECKER_API_KEY':'','NETCHECKER_ALLOWED_SCOPES':''}))

    def tearDown(self):
        self.stack.close(); self.directory.cleanup()

    def request(self,url,headers=()):
        status,body = asyncio.run(asgi_get(url,headers))
        return status,json.loads(body)

    def put(self,url,payload,headers=()):
        status,body = asyncio.run(asgi_request('PUT',url,headers,payload))
        return status,json.loads(body)

    def post(self,url,payload,headers=()):
        status,body = asyncio.run(asgi_request('POST',url,headers,payload))
        return status,json.loads(body)

    def delete(self,url,headers=()):
        status,body = asyncio.run(asgi_request('DELETE',url,headers))
        return status,json.loads(body)

    def test_numeric_pagination(self):
        status,data = self.request(f'/api/devices?network_id={self.network}&limit=1')
        self.assertEqual(200,status)
        self.assertEqual('192.0.2.2',data['devices'][0]['ip'])
        self.assertEqual(2,data['total'])
        status,other = self.request(f'/api/devices?network_id={self.network}&limit=1&offset=1')
        self.assertEqual(200,status)
        self.assertEqual('192.0.2.10',other['devices'][0]['ip'])

    def test_detail_has_new_evidence_fields(self):
        status,data = self.request(f'/api/devices/{self.ids[0]}?network_id={self.network}')
        self.assertEqual(200,status)
        for field in ('mac_analysis','os_summary','os_claims','interfaces','identity_candidates','port_history'):
            self.assertIn(field,data)

    def test_wrong_network_device_hidden(self):
        self.assertEqual(404,self.request(f'/api/devices/{self.ids[0]}?network_id={self.other_network}')[0])

    def test_scope_permissions_cover_all_apis(self):
        with patch.dict(os.environ,{'NETCHECKER_ALLOWED_SCOPES':'1'}):
            self.assertEqual(1,self.request('/api/networks')[1]['count'])
            self.assertEqual(1,len(self.request('/api/networks/scopes')[1]['scopes']))
            self.assertEqual(2,self.request('/api/devices')[1]['total'])
            for url in (f'/api/devices?network_id={self.other_network}',
                        f'/api/topology?network_id={self.other_network}',
                        f'/api/topology/snapshots?network_id={self.other_network}',
                        f'/api/topology/compare?network_id={self.other_network}&before={self.snapshots[2]}&after={self.snapshots[2]}'):
                self.assertEqual(404,self.request(url)[0])

    def test_api_key(self):
        with patch.dict(os.environ,{'NETCHECKER_API_KEY':'synthetic-key'}):
            self.assertEqual(401,self.request('/api/networks')[0])
            self.assertEqual(200,self.request('/api/networks',[(b'x-netchecker-key',b'synthetic-key')])[0])

    def test_latest_topology_excludes_running_snapshot(self):
        status,data = self.request(f'/api/topology?network_id={self.network}')
        self.assertEqual(200,status)
        self.assertEqual(self.snapshots[1],data['snapshot']['id'])

    def test_compare_does_not_cross_networks(self):
        self.assertEqual(404,self.request(f'/api/topology/compare?network_id={self.network}&before={self.snapshots[0]}&after={self.snapshots[2]}')[0])
        self.assertEqual(200,self.request(f'/api/topology/compare?network_id={self.network}&before={self.snapshots[0]}&after={self.snapshots[1]}')[0])

    def test_topology_layout_round_trips_and_swaps_positions(self):
        url = f'/api/topology/layout?network_id={self.network}'
        status, empty = self.request(url)
        self.assertEqual(200, status)
        self.assertIsNone(empty['layout'])
        self.assertEqual([], empty['positions'])

        initial = {'layout_id':None,'positions':[
            {'device_id':self.ids[0],'grid_x':5,'grid_y':-2},
            {'device_id':self.ids[1],'grid_x':6,'grid_y':-2},
        ]}
        status, saved = self.put(url, initial)
        self.assertEqual(200, status)
        layout_id = saved['layout']['id']
        self.assertTrue(saved['saved'])

        # Each request opens a fresh SQLite connection, as after a page reload
        # or backend restart.
        status, reloaded = self.request(url)
        self.assertEqual(200, status)
        self.assertEqual(layout_id, reloaded['layout']['id'])
        self.assertEqual({
            self.ids[0]:(5,-2), self.ids[1]:(6,-2)
        }, {row['device_id']:(row['grid_x'],row['grid_y']) for row in reloaded['positions']})

        swapped = {'layout_id':layout_id,'positions':[
            {'device_id':self.ids[0],'grid_x':6,'grid_y':-2},
            {'device_id':self.ids[1],'grid_x':5,'grid_y':-2},
        ]}
        self.assertEqual(200, self.put(url, swapped)[0])
        status, after_swap = self.request(url)
        self.assertEqual(200, status)
        self.assertEqual({
            self.ids[0]:(6,-2), self.ids[1]:(5,-2)
        }, {row['device_id']:(row['grid_x'],row['grid_y']) for row in after_swap['positions']})

    def test_manual_nodes_create_edit_hide_show_and_delete_without_scanner_rows(self):
        layout_url = f'/api/topology/layout?network_id={self.network}'
        layout_status, saved = self.put(layout_url, {'layout_id':None,'positions':[
            {'device_id':self.ids[0],'grid_x':5,'grid_y':-2},
        ]})
        self.assertEqual(200,layout_status)
        layout_id = saved['layout']['id']

        connection = sqlite3.connect(self.path)
        counts_before = tuple(connection.execute(
            'SELECT (SELECT COUNT(*) FROM devices),(SELECT COUNT(*) FROM addresses),'
            '(SELECT COUNT(*) FROM networks)'
        ).fetchone())
        connection.close()

        base_url = f'/api/topology/manual-nodes?network_id={self.network}'
        status, created = self.post(base_url,{
            'layout_id':layout_id,'node_type':'switch','label':'Core-Switch',
            'properties':{'rack':'A1','ports':24},'linked_device_id':self.ids[0],
            'grid_x':3,'grid_y':4,
        })
        self.assertEqual(200,status)
        switch = created['node']
        self.assertEqual('switch',switch['node_type'])
        self.assertEqual({'rack':'A1','ports':24},switch['properties'])
        self.assertEqual(self.ids[0],switch['linked_device_id'])
        self.assertIsNone(switch['linked_network_id'])

        status, network_node = self.post(base_url,{
            'layout_id':layout_id,'node_type':'network','label':'192.0.2.7/24',
            'grid_x':8,'grid_y':0,
        })
        self.assertEqual(200,status)
        network_node = network_node['node']
        self.assertEqual('192.0.2.0/24',network_node['label'])
        self.assertEqual(self.network,network_node['linked_network_id'])
        self.assertEqual(409,self.post(base_url,{
            'layout_id':layout_id,'node_type':'network','label':'192.0.2.0/24',
            'grid_x':9,'grid_y':0,
        })[0])

        self.assertEqual(404,self.post(base_url,{
            'layout_id':layout_id,'node_type':'router','label':'Foreign device',
            'linked_device_id':self.ids[2],'grid_x':10,'grid_y':0,
        })[0])

        edit_url = f'/api/topology/manual-nodes/{switch["id"]}?network_id={self.network}'
        status, updated = self.put(edit_url,{
            'node_type':'router','label':'Edge Router','properties':{'hostname':'gateway-1'},
        })
        self.assertEqual(200,status)
        self.assertEqual('router',updated['node']['node_type'])
        self.assertEqual({'hostname':'gateway-1'},updated['node']['properties'])
        self.assertNotIn('is_hidden',updated['node'])

        self.assertEqual(422,self.put(edit_url,{'is_hidden':True})[0])

        # The batch-position API stores manual positions alongside device
        # positions and rejects collisions across the two node origins.
        self.assertEqual(409,self.put(layout_url,{
            'layout_id':layout_id,'positions':[],
            'manual_positions':[{'manual_node_id':switch['id'],'grid_x':5,'grid_y':-2}],
        })[0])
        status, moved = self.put(layout_url,{
            'layout_id':layout_id,'positions':[],
            'manual_positions':[
                {'manual_node_id':switch['id'],'grid_x':-7,'grid_y':4},
                {'manual_node_id':network_node['id'],'grid_x':8,'grid_y':1},
            ],
        })
        self.assertEqual(200,status)
        self.assertEqual({
            switch['id']:(-7,4),network_node['id']:(8,1),
        },{node['id']:(node['grid_x'],node['grid_y']) for node in moved['manual_nodes']})
        self.assertEqual({self.ids[0]:(5,-2)}, {
            row['device_id']:(row['grid_x'],row['grid_y']) for row in moved['positions']
        })

        self.assertEqual(200,self.delete(edit_url)[0])
        self.assertEqual(200,self.delete(
            f'/api/topology/manual-nodes/{network_node["id"]}?network_id={self.network}'
        )[0])
        self.assertEqual([],self.request(layout_url)[1]['manual_nodes'])

        connection = sqlite3.connect(self.path)
        self.assertEqual(counts_before,tuple(connection.execute(
            'SELECT (SELECT COUNT(*) FROM devices),(SELECT COUNT(*) FROM addresses),'
            '(SELECT COUNT(*) FROM networks)'
        ).fetchone()))
        self.assertEqual({self.ids[0]:(5,-2)}, {
            row[0]:(row[1],row[2])
            for row in connection.execute(
                'SELECT device_id,grid_x,grid_y FROM topology_layout_positions WHERE layout_id=?',
                (layout_id,),
            )
        })
        connection.close()

    def test_layout_keeps_missing_devices_and_does_not_move_for_new_devices(self):
        url = f'/api/topology/layout?network_id={self.network}'
        status, saved = self.put(url, {'layout_id':None,'positions':[
            {'device_id':self.ids[0],'grid_x':-4,'grid_y':9},
        ]})
        self.assertEqual(200, status)

        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("UPDATE device_presence SET state='missing' WHERE network_id=? AND device_id=?",
                           (self.network,self.ids[0]))
        run = database.start_scan_run(connection,self.network,'discovery')
        new_device = database.save_discovery_host(connection,self.network,run,{
            'ip':'192.0.2.99','mac':'00:11:22:33:44:99'
        })
        database.finish_scan_run(connection,run)
        connection.commit()
        connection.close()

        status, layout = self.request(url)
        self.assertEqual(200, status)
        positions = {row['device_id']:(row['grid_x'],row['grid_y']) for row in layout['positions']}
        self.assertEqual((-4,9),positions[self.ids[0]])
        self.assertNotIn(new_device,positions)

    def test_layout_rejects_invalid_positions_and_cross_network_ids(self):
        url = f'/api/topology/layout?network_id={self.network}'
        bad_values = [
            {'layout_id':None,'positions':[{'device_id':self.ids[0],'grid_x':1000001,'grid_y':0}]},
            {'layout_id':None,'positions':[{'device_id':self.ids[0],'grid_x':0.5,'grid_y':0}]},
            {'layout_id':None,'positions':[
                {'device_id':self.ids[0],'grid_x':0,'grid_y':0},
                {'device_id':self.ids[1],'grid_x':0,'grid_y':0},
            ]},
        ]
        for payload in bad_values:
            self.assertEqual(422,self.put(url,payload)[0])

        foreign_device = self.ids[2]
        self.assertEqual(404,self.put(url,{'layout_id':None,'positions':[
            {'device_id':foreign_device,'grid_x':1,'grid_y':1}
        ]})[0])

        status, saved = self.put(url,{'layout_id':None,'positions':[
            {'device_id':self.ids[0],'grid_x':1,'grid_y':1}
        ]})
        self.assertEqual(200,status)
        self.assertEqual(404,self.request(
            f'/api/topology/layout?network_id={self.other_network}&layout_id={saved["layout"]["id"]}'
        )[0])
        self.assertEqual(404,self.put(
            f'/api/topology/layout?network_id={self.other_network}',
            {'layout_id':saved['layout']['id'],'positions':[
                {'device_id':self.ids[2],'grid_x':1,'grid_y':1}
            ]}
        )[0])

    def test_layout_write_error_rolls_back_and_returns_service_error(self):
        connection = sqlite3.connect(self.path)
        connection.execute("""CREATE TRIGGER reject_topology_position
            BEFORE INSERT ON topology_layout_positions
            BEGIN SELECT RAISE(ABORT,'synthetic storage failure'); END""")
        connection.commit()
        connection.close()

        status, _ = self.put(f'/api/topology/layout?network_id={self.network}', {
            'layout_id':None,'positions':[{'device_id':self.ids[0],'grid_x':2,'grid_y':3}]
        })
        self.assertEqual(503,status)
        self.assertIsNone(self.request(f'/api/topology/layout?network_id={self.network}')[1]['layout'])

    def test_rooms_persist_memberships_and_move_contents_as_one_layout_change(self):
        network_url = f'/api/topology/layout?network_id={self.network}'
        status, layout = self.put(network_url, {'layout_id':None,'positions':[
            {'device_id':self.ids[0],'grid_x':0,'grid_y':0},
            {'device_id':self.ids[1],'grid_x':1,'grid_y':0},
        ]})
        self.assertEqual(200,status)
        layout_id = layout['layout']['id']
        status, created = self.post(f'/api/topology/rooms?network_id={self.network}', {
            'layout_id':layout_id,'name':'Büro 1','description':'Arbeitsplätze',
            'grid_x':0,'grid_y':0,'grid_width':5,'grid_height':4,
            'grid_cell_width':420,'grid_cell_height':388,
        })
        self.assertEqual(200,status)
        room_id = created['room']['id']
        self.assertTrue(created['room']['move_contents'])
        status, renamed = self.put(f'/api/topology/rooms/{room_id}?network_id={self.network}', {
            'name':'Büro Haupt','description':'Mehrere Arbeitsplätze',
        })
        self.assertEqual(200,status)
        self.assertEqual('Büro Haupt',renamed['name'])
        status, copied = asyncio.run(asgi_request('POST',
            f'/api/topology/rooms/{room_id}/duplicate?network_id={self.network}'))
        copied=json.loads(copied)
        self.assertEqual(200,status)
        self.assertEqual('Büro Haupt (Kopie)',copied['room']['name'])
        self.assertEqual([],copied['room']['device_ids'])
        copy_id=copied['room']['id']
        status, _ = asyncio.run(asgi_request('DELETE',
            f'/api/topology/rooms/{copy_id}?network_id={self.network}'))
        self.assertEqual(200,status)
        for device_id in self.ids[:2]:
            status, _ = self.put(
                f'/api/topology/rooms/assignment?network_id={self.network}&layout_id={layout_id}',
                {'room_id':room_id,'device_id':device_id},
            )
            self.assertEqual(200,status)
        status, manual = self.post(f'/api/topology/manual-nodes?network_id={self.network}', {
            'layout_id':layout_id,'node_type':'switch','label':'Switch Büro',
            'grid_x':2,'grid_y':1,
        })
        self.assertEqual(200,status)
        manual_id = manual['node']['id']
        status, second_manual = self.post(f'/api/topology/manual-nodes?network_id={self.network}', {
            'layout_id':layout_id,'node_type':'generic','label':'PC Raum',
            'grid_x':8,'grid_y':1,
        })
        self.assertEqual(200,status)
        second_manual_id = second_manual['node']['id']
        status, _ = self.put(
            f'/api/topology/rooms/assignment?network_id={self.network}&layout_id={layout_id}',
            {'room_id':room_id,'manual_node_id':manual_id},
        )
        self.assertEqual(200,status)
        status, _ = self.put(
            f'/api/topology/rooms/assignment?network_id={self.network}&layout_id={layout_id}',
            {'room_id':room_id,'manual_node_id':second_manual_id},
        )
        self.assertEqual(200,status)
        # Resizing leaves assigned nodes where they are, even when the room
        # is configured to move its explicitly assigned contents.
        status, resized = self.put(f'/api/topology/rooms/{room_id}/geometry?network_id={self.network}', {
            'grid_x':-1,'grid_y':-1,'grid_width':6,'grid_height':5,
        })
        self.assertEqual(200,status)
        unchanged=self.request(network_url)[1]
        self.assertEqual((0,0),{item['device_id']:(item['grid_x'],item['grid_y'])
            for item in unchanged['positions']}[self.ids[0]])
        self.assertTrue(resized['room']['move_contents'])
        outside_manual=next(item for item in unchanged['manual_nodes'] if item['id']==second_manual_id)
        self.assertEqual((8,1),(outside_manual['grid_x'],outside_manual['grid_y']))

        # Older rooms may have a stored opt-out. A room move now always moves
        # explicitly assigned contents; the saved preference is no longer a
        # user-facing switch and must not disable the move operation.
        status, updated_room = self.put(
            f'/api/topology/rooms/{room_id}?network_id={self.network}', {'move_contents':False})
        self.assertEqual(200,status)
        self.assertFalse(updated_room['move_contents'])

        status, moved = self.put(f'/api/topology/rooms/{room_id}/geometry?network_id={self.network}', {
            'grid_x':0,'grid_y':1,'grid_width':6,'grid_height':5,'move_contents':True,
        })
        self.assertEqual(200,status)
        self.assertFalse(moved['room']['move_contents'])
        self.assertEqual([self.ids[0],self.ids[1]],moved['room']['device_ids'])
        self.assertEqual([manual_id,second_manual_id],moved['room']['manual_node_ids'])
        layout = self.request(network_url)[1]
        coordinates = {item['device_id']:(item['grid_x'],item['grid_y']) for item in layout['positions']}
        self.assertEqual((1,2),coordinates[self.ids[0]])
        self.assertEqual((2,2),coordinates[self.ids[1]])
        manual_position = next(item for item in layout['manual_nodes'] if item['id']==manual_id)
        self.assertEqual((3,3),(manual_position['grid_x'],manual_position['grid_y']))
        second_position = next(item for item in layout['manual_nodes'] if item['id']==second_manual_id)
        self.assertEqual((9,3),(second_position['grid_x'],second_position['grid_y']))
        self.assertEqual({'top','right','bottom','left'},set(moved['room']['connection_points']))

        status, _ = self.put(
            f'/api/topology/rooms/assignment?network_id={self.network}&layout_id={layout_id}',
            {'room_id':None,'device_id':self.ids[1]},
        )
        self.assertEqual(200,status)
        status, rooms = self.request(f'/api/topology/rooms?network_id={self.network}&layout_id={layout_id}')
        self.assertEqual(200,status)
        self.assertEqual([self.ids[0]],rooms['rooms'][0]['device_ids'])

        status, _ = asyncio.run(asgi_request('DELETE',
            f'/api/topology/rooms/{room_id}?network_id={self.network}'))
        self.assertEqual(200,status)
        after_delete = self.request(network_url)[1]
        self.assertEqual((1,2),(after_delete['positions'][0]['grid_x'],after_delete['positions'][0]['grid_y']))
        self.assertEqual([],after_delete['rooms'])

    def test_nested_rooms_move_as_a_subtree_and_reject_cycles(self):
        _, saved = self.put(f'/api/topology/layout?network_id={self.network}', {
            'layout_id':None,'positions':[
                {'device_id':self.ids[0],'grid_x':5,'grid_y':5},
                {'device_id':self.ids[1],'grid_x':6,'grid_y':5},
            ],
        })
        layout_id=saved['layout']['id']

        def add_room(network_id,layout_id,name,x,y,width,height,parent=None):
            status,result=self.post(f'/api/topology/rooms?network_id={network_id}',{
                'layout_id':layout_id,'parent_room_id':parent,'name':name,
                'grid_x':x,'grid_y':y,'grid_width':width,'grid_height':height,
                'grid_cell_width':400,'grid_cell_height':360,
            })
            self.assertEqual(200,status,result)
            return result['room']

        root=add_room(self.network,layout_id,'Standort',0,0,20,20)
        child=add_room(self.network,layout_id,'Etage',2,2,12,12,root['id'])
        nested=add_room(self.network,layout_id,'Serverraum',4,4,6,6,child['id'])
        target=add_room(self.network,layout_id,'Nebengebäude',30,30,20,20)
        self.assertEqual(root['id'],child['parent_room_id'])
        self.assertEqual(child['id'],nested['parent_room_id'])
        connection=sqlite3.connect(self.path)
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                'UPDATE topology_rooms SET parent_room_id=? WHERE id=?',
                (nested['id'],root['id']),
            )
        connection.close()

        _, manual=self.post(f'/api/topology/manual-nodes?network_id={self.network}',{
            'layout_id':layout_id,'node_type':'switch','label':'Server Switch','grid_x':8,'grid_y':8,
        })
        _, obstacle=self.post(f'/api/topology/manual-nodes?network_id={self.network}',{
            'layout_id':layout_id,'node_type':'generic','label':'Unassigned','grid_x':14,'grid_y':14,
        })
        for device_id in self.ids[:2]:
            status,_=self.put(
                f'/api/topology/rooms/assignment?network_id={self.network}&layout_id={layout_id}',
                {'room_id':nested['id'],'device_id':device_id},
            )
            self.assertEqual(200,status)
        status,_=self.put(
            f'/api/topology/rooms/assignment?network_id={self.network}&layout_id={layout_id}',
            {'room_id':nested['id'],'manual_node_id':manual['node']['id']},
        )
        self.assertEqual(200,status)

        status,collision_layout=self.put(f'/api/topology/layout?network_id={self.network}',{
            'layout_id':layout_id,'positions':[],
            'manual_positions':[{'manual_node_id':obstacle['node']['id'],'grid_x':6,'grid_y':7}],
        })
        self.assertEqual(200,status,collision_layout)
        status,collision=self.put(f"/api/topology/rooms/{root['id']}/geometry?network_id={self.network}",{
            'grid_x':1,'grid_y':2,'grid_width':20,'grid_height':20,'move_contents':True,
        })
        self.assertEqual(409,status,collision)
        unchanged=self.request(f'/api/topology/layout?network_id={self.network}')[1]
        self.assertEqual((5,5),next((item['grid_x'],item['grid_y']) for item in unchanged['positions']
            if item['device_id']==self.ids[0]))
        self.assertEqual((0,0),next((room['grid_x'],room['grid_y']) for room in unchanged['rooms']
            if room['id']==root['id']))
        status,_=self.put(f'/api/topology/layout?network_id={self.network}',{
            'layout_id':layout_id,'positions':[],
            'manual_positions':[{'manual_node_id':obstacle['node']['id'],'grid_x':14,'grid_y':14}],
        })
        self.assertEqual(200,status)

        status,moved=self.put(f"/api/topology/rooms/{root['id']}/geometry?network_id={self.network}",{
            'grid_x':1,'grid_y':2,'grid_width':20,'grid_height':20,'move_contents':True,
        })
        self.assertEqual(200,status,moved)
        rooms={room['id']:room for room in moved['rooms']}
        self.assertEqual((3,4,root['id']),(
            rooms[child['id']]['grid_x'],rooms[child['id']]['grid_y'],rooms[child['id']]['parent_room_id']))
        self.assertEqual((5,6,child['id']),(
            rooms[nested['id']]['grid_x'],rooms[nested['id']]['grid_y'],rooms[nested['id']]['parent_room_id']))
        self.assertEqual((8,6),(
            rooms[nested['id']]['connection_points']['top']['x'],
            rooms[nested['id']]['connection_points']['top']['y']))
        layout=self.request(f'/api/topology/layout?network_id={self.network}')[1]
        positions={item['device_id']:(item['grid_x'],item['grid_y']) for item in layout['positions']}
        self.assertEqual((6,7),positions[self.ids[0]])
        self.assertEqual((7,7),positions[self.ids[1]])
        manual_after=next(item for item in layout['manual_nodes'] if item['id']==manual['node']['id'])
        self.assertEqual((9,10),(manual_after['grid_x'],manual_after['grid_y']))

        status,resized=self.put(f"/api/topology/rooms/{root['id']}/geometry?network_id={self.network}",{
            'grid_x':1,'grid_y':2,'grid_width':19,'grid_height':19,
        })
        self.assertEqual(200,status,resized)
        rooms={room['id']:room for room in resized['rooms']}
        self.assertEqual((3,4),(rooms[child['id']]['grid_x'],rooms[child['id']]['grid_y']))

        status,cycle=self.put(f"/api/topology/rooms/{root['id']}/geometry?network_id={self.network}",{
            'grid_x':5,'grid_y':6,'grid_width':20,'grid_height':20,
            'parent_room_id':nested['id'],'move_contents':True,
        })
        self.assertEqual(409,status,cycle)
        status,too_small=self.put(f"/api/topology/rooms/{root['id']}/geometry?network_id={self.network}",{
            'grid_x':1,'grid_y':2,'grid_width':4,'grid_height':4,
        })
        self.assertEqual(409,status,too_small)
        status,outside=self.put(f"/api/topology/rooms/{child['id']}/geometry?network_id={self.network}",{
            'grid_x':3,'grid_y':4,'grid_width':22,'grid_height':12,
        })
        self.assertEqual(409,status,outside)

        status,reparented=self.put(f"/api/topology/rooms/{child['id']}/geometry?network_id={self.network}",{
            'grid_x':31,'grid_y':32,'grid_width':12,'grid_height':12,
            'parent_room_id':target['id'],'move_contents':True,
        })
        self.assertEqual(200,status,reparented)
        rooms={room['id']:room for room in reparented['rooms']}
        self.assertEqual(target['id'],rooms[child['id']]['parent_room_id'])
        self.assertEqual((33,34),(rooms[nested['id']]['grid_x'],rooms[nested['id']]['grid_y']))
        layout=self.request(f'/api/topology/layout?network_id={self.network}')[1]
        positions={item['device_id']:(item['grid_x'],item['grid_y']) for item in layout['positions']}
        self.assertEqual((34,35),positions[self.ids[0]])

        status,detached=self.put(f"/api/topology/rooms/{child['id']}/geometry?network_id={self.network}",{
            'grid_x':31,'grid_y':32,'grid_width':12,'grid_height':12,'parent_room_id':None,
        })
        self.assertEqual(200,status,detached)
        self.assertIsNone(next(room for room in detached['rooms'] if room['id']==child['id'])['parent_room_id'])

        _, other_layout=self.put(f'/api/topology/layout?network_id={self.other_network}',{
            'layout_id':None,'positions':[{'device_id':self.ids[2],'grid_x':0,'grid_y':0}],
        })
        foreign=add_room(self.other_network,other_layout['layout']['id'],'Fremdes Layout',0,0,5,5)
        status,result=self.put(f"/api/topology/rooms/{child['id']}/geometry?network_id={self.network}",{
            'grid_x':31,'grid_y':32,'grid_width':12,'grid_height':12,
            'parent_room_id':foreign['id'],
        })
        self.assertEqual(404,status,result)

    def test_room_move_collision_rolls_back_all_members_and_geometry(self):
        network_url = f'/api/topology/layout?network_id={self.network}'
        _, saved = self.put(network_url, {'layout_id':None,'positions':[
            {'device_id':self.ids[0],'grid_x':0,'grid_y':0},
            {'device_id':self.ids[1],'grid_x':3,'grid_y':0},
        ]})
        layout_id=saved['layout']['id']
        _, created = self.post(f'/api/topology/rooms?network_id={self.network}', {
            'layout_id':layout_id,'name':'Lab','grid_x':0,'grid_y':0,'grid_width':4,'grid_height':3,
            'grid_cell_width':420,'grid_cell_height':388,
        })
        room_id=created['room']['id']
        self.put(f'/api/topology/rooms/{room_id}?network_id={self.network}',{'move_contents':True})
        status, manual=self.post(f'/api/topology/manual-nodes?network_id={self.network}', {
            'layout_id':layout_id,'node_type':'switch','label':'Assigned switch',
            'grid_x':1,'grid_y':1,
        })
        self.assertEqual(200,status)
        manual_id=manual['node']['id']
        self.put(f'/api/topology/rooms/assignment?network_id={self.network}&layout_id={layout_id}', {
            'room_id':room_id,'device_id':self.ids[0],
        })
        self.put(f'/api/topology/rooms/assignment?network_id={self.network}&layout_id={layout_id}', {
            'room_id':room_id,'manual_node_id':manual_id,
        })
        status, result = self.put(f'/api/topology/rooms/{room_id}/geometry?network_id={self.network}', {
            'grid_x':3,'grid_y':0,'grid_width':4,'grid_height':3,'move_contents':True,
        })
        self.assertEqual(409,status)
        self.assertIn('kollidiert',result['detail'])
        after=self.request(network_url)[1]
        self.assertEqual(0,after['rooms'][0]['grid_x'])
        coordinates={item['device_id']:(item['grid_x'],item['grid_y']) for item in after['positions']}
        self.assertEqual((0,0),coordinates[self.ids[0]])
        self.assertEqual((3,0),coordinates[self.ids[1]])
        persisted_manual=next(item for item in after['manual_nodes'] if item['id']==manual_id)
        self.assertEqual((1,1),(persisted_manual['grid_x'],persisted_manual['grid_y']))
        self.assertEqual([manual_id],after['rooms'][0]['manual_node_ids'])

    def test_room_geometry_reports_actual_422_and_clean_resize_round_trips(self):
        _, saved=self.put(f'/api/topology/layout?network_id={self.network}', {
            'layout_id':None,'positions':[{'device_id':self.ids[0],'grid_x':7,'grid_y':8}],
        })
        layout_id=saved['layout']['id']
        status, created=self.post(f'/api/topology/rooms?network_id={self.network}', {
            'layout_id':layout_id,'name':'Geometrie','grid_x':0,'grid_y':0,
            'grid_width':4,'grid_height':3,'grid_cell_width':420,'grid_cell_height':388,
        })
        self.assertEqual(200,status)
        room=created['room']
        self.assertTrue(room['move_contents'])

        # The old resize code spread the complete room response into the
        # geometry request. Config.extra='forbid' rejects those extra fields.
        oversized=dict(room)
        oversized.update({'grid_x':1,'grid_y':0,'grid_width':5,'grid_height':3})
        status, error=self.put(
            f'/api/topology/rooms/{room["id"]}/geometry?network_id={self.network}',oversized)
        self.assertEqual(422,status)
        self.assertIsInstance(error['detail'],list)
        rejected_fields={issue['loc'][-1] for issue in error['detail'] if issue.get('loc')}
        self.assertTrue(any(issue.get('type') == 'extra_forbidden' for issue in error['detail']))
        self.assertTrue({'id','layout_id','name'} & rejected_fields)

        clean={'grid_x':1,'grid_y':0,'grid_width':5,'grid_height':3}
        self.assertEqual(200,self.put(
            f'/api/topology/rooms/{room["id"]}/geometry?network_id={self.network}',clean)[0])
        layout=self.request(f'/api/topology/layout?network_id={self.network}')[1]
        self.assertEqual((1,0,5,3),tuple(layout['rooms'][0][key] for key in
            ('grid_x','grid_y','grid_width','grid_height')))
        self.assertEqual((7,8),(layout['positions'][0]['grid_x'],layout['positions'][0]['grid_y']))

        # Exercise the eight persisted edge/corner geometries. Changes to
        # grid_x/grid_y here model west/north handles and must never translate
        # assigned content unless the request explicitly says it is a move.
        resize_shapes=[(-1,-1,7,5),(1,-2,5,5),(1,-1,7,4),(1,0,7,3),
                       (1,0,6,5),(1,0,5,5),(0,0,6,5),(0,0,5,5)]
        for grid_x,grid_y,grid_width,grid_height in resize_shapes:
            status,_=self.put(f'/api/topology/rooms/{room["id"]}/geometry?network_id={self.network}',{
                'grid_x':grid_x,'grid_y':grid_y,
                'grid_width':grid_width,'grid_height':grid_height,
            })
            self.assertEqual(200,status)
            persisted=self.request(f'/api/topology/layout?network_id={self.network}')[1]
            self.assertEqual((7,8),(persisted['positions'][0]['grid_x'],persisted['positions'][0]['grid_y']))

    def test_manual_room_assignment_can_be_outside_and_clear_without_moving_device(self):
        url=f'/api/topology/layout?network_id={self.network}'
        _, saved=self.put(url,{'layout_id':None,'positions':[
            {'device_id':self.ids[0],'grid_x':12,'grid_y':-4},
        ]})
        layout_id=saved['layout']['id']
        _, room=self.post(f'/api/topology/rooms?network_id={self.network}',{
            'layout_id':layout_id,'name':'Innenraum','grid_x':0,'grid_y':0,
            'grid_width':3,'grid_height':3,'grid_cell_width':420,'grid_cell_height':388,
        })
        room_id=room['room']['id']
        self.assertEqual(200,self.put(url,{
            'layout_id':layout_id,'positions':[{'device_id':self.ids[0],'grid_x':12,'grid_y':-4}],
            'room_assignments':[{'room_id':room_id,'device_id':self.ids[0],
                                 'grid_x':12,'grid_y':-4}],
        })[0])
        after_assign=self.request(url)[1]
        self.assertEqual([self.ids[0]],after_assign['rooms'][0]['device_ids'])
        self.assertEqual((12,-4),(after_assign['positions'][0]['grid_x'],after_assign['positions'][0]['grid_y']))
        self.assertEqual(200,self.put(url,{
            'layout_id':layout_id,'positions':[{'device_id':self.ids[0],'grid_x':12,'grid_y':-4}],
            'room_assignments':[{'room_id':None,'device_id':self.ids[0],
                                 'grid_x':12,'grid_y':-4}],
        })[0])
        after_clear=self.request(url)[1]
        self.assertEqual([],after_clear['rooms'][0]['device_ids'])
        self.assertEqual((12,-4),(after_clear['positions'][0]['grid_x'],after_clear['positions'][0]['grid_y']))

    def test_room_rejects_invalid_geometry_and_other_network_layout(self):
        _, saved=self.put(f'/api/topology/layout?network_id={self.network}', {
            'layout_id':None,'positions':[{'device_id':self.ids[0],'grid_x':0,'grid_y':0}],
        })
        layout_id=saved['layout']['id']
        status, _=self.post(f'/api/topology/rooms?network_id={self.network}', {
            'layout_id':layout_id,'name':'Zu klein','grid_x':0,'grid_y':0,'grid_width':1,'grid_height':3,
        })
        self.assertEqual(422,status)
        status, _=self.post(f'/api/topology/rooms?network_id={self.other_network}', {
            'layout_id':layout_id,'name':'Fremd','grid_x':0,'grid_y':0,'grid_width':3,'grid_height':3,
            'grid_cell_width':420,'grid_cell_height':388,
        })
        self.assertEqual(404,status)
        connection=sqlite3.connect(self.path)
        alternate=connection.execute(
            "INSERT INTO topology_layouts(network_id,name,is_default) VALUES(?,'Alternative',0)",
            (self.network,),
        ).lastrowid
        connection.commit(); connection.close()
        status, alternate_room=self.post(f'/api/topology/rooms?network_id={self.network}', {
            'layout_id':alternate,'name':'Alternative Raum','grid_x':0,'grid_y':0,
            'grid_width':3,'grid_height':3,'grid_cell_width':420,'grid_cell_height':388,
        })
        self.assertEqual(200,status)
        self.assertEqual([],self.request(f'/api/topology/rooms?network_id={self.network}&layout_id={layout_id}')[1]['rooms'])
        self.assertEqual([alternate_room['room']['id']],
                         [room['id'] for room in self.request(
                             f'/api/topology/rooms?network_id={self.network}&layout_id={alternate}')[1]['rooms']])

    def test_topology_layout_migration_is_additive_and_repeatable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'existing-copy.db'
            connection = sqlite3.connect(path)
            connection.row_factory = sqlite3.Row
            connection.execute('PRAGMA foreign_keys=ON')
            schema.initialize_database(connection)
            network = database.save_network(connection,'198.51.100.0/24','copy0',None)
            device = connection.execute(
                "INSERT INTO devices(mac,hostname) VALUES('00:AA:BB:CC:DD:EE','saved-host')"
            ).lastrowid
            connection.execute(
                'INSERT INTO addresses(device_id,network_id,ip) VALUES(?,?,?)',
                (device,network,'198.51.100.7'),
            )
            connection.execute(
                "INSERT INTO observations(network_id,device_id,observation_type,data_json) "
                "VALUES(?,?,'host_discovery','{}')", (network,device),
            )
            layout = connection.execute(
                "INSERT INTO topology_layouts(network_id,name,is_default) VALUES(?,'Standard',1)",
                (network,),
            ).lastrowid
            connection.execute(
                'INSERT INTO topology_layout_positions(layout_id,device_id,grid_x,grid_y) VALUES(?,?,?,?)',
                (layout,device,-3,8),
            )
            connection.commit()
            before = tuple(connection.execute(
                'SELECT id,cidr,interface FROM networks WHERE id=?',(network,)
            ).fetchone())
            observation_count = connection.execute('SELECT COUNT(*) FROM observations').fetchone()[0]
            saved_position = tuple(connection.execute(
                'SELECT layout_id,device_id,grid_x,grid_y FROM topology_layout_positions'
            ).fetchone())

            connection.execute('DROP TABLE topology_layout_links')
            connection.execute('DROP TABLE topology_manual_nodes')
            connection.execute('DELETE FROM schema_migrations WHERE version=6')
            connection.execute('PRAGMA user_version=5')
            connection.commit()
            schema.initialize_database(connection)
            schema.initialize_database(connection)

            self.assertEqual(schema.SCHEMA_VERSION,connection.execute('PRAGMA user_version').fetchone()[0])
            self.assertEqual(before,tuple(connection.execute(
                'SELECT id,cidr,interface FROM networks WHERE id=?',(network,)
            ).fetchone()))
            self.assertEqual(observation_count,connection.execute('SELECT COUNT(*) FROM observations').fetchone()[0])
            self.assertEqual(saved_position,tuple(connection.execute(
                'SELECT layout_id,device_id,grid_x,grid_y FROM topology_layout_positions'
            ).fetchone()))
            self.assertTrue({'topology_layouts','topology_layout_positions',
                             'topology_manual_nodes','topology_layout_links','topology_rooms',
                             'topology_room_devices','topology_room_manual_nodes'} <= {
                row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            })
            connection.close()

    def test_schema_v6_to_v8_adds_room_tables_without_changing_layouts(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        device=self.ids[0]
        connection.execute("INSERT INTO topology_layouts(network_id,name,is_default) VALUES(?,'Room migration',0)",
                            (self.network,))
        layout=connection.execute("SELECT id FROM topology_layouts WHERE name='Room migration'").fetchone()['id']
        connection.execute('INSERT INTO topology_layout_positions(layout_id,device_id,grid_x,grid_y) VALUES(?,?,?,?)',
                           (layout,device,-8,11))
        connection.commit()
        for table in ('topology_room_manual_nodes','topology_room_devices','topology_rooms'):
            connection.execute(f'DROP TABLE {table}')
        connection.execute('ALTER TABLE topology_layouts DROP COLUMN grid_cell_height')
        connection.execute('ALTER TABLE topology_layouts DROP COLUMN grid_cell_width')
        connection.execute('DELETE FROM schema_migrations WHERE version=7')
        connection.execute('PRAGMA user_version=6')
        connection.commit()
        schema.initialize_database(connection)
        schema.initialize_database(connection)
        saved=connection.execute(
            'SELECT grid_x,grid_y FROM topology_layout_positions WHERE layout_id=? AND device_id=?',
            (layout,device),
        ).fetchone()
        self.assertEqual((-8,11),tuple(saved))
        self.assertEqual(8,connection.execute('PRAGMA user_version').fetchone()[0])
        self.assertEqual(3,connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN "
            "('topology_rooms','topology_room_devices','topology_room_manual_nodes')"
        ).fetchone()[0])
        connection.close()

    def test_schema_v7_to_v8_adds_parent_room_and_preserves_existing_links(self):
        connection=sqlite3.connect(self.path)
        connection.row_factory=sqlite3.Row
        connection.execute(
            "INSERT INTO topology_layouts(network_id,name,is_default) VALUES(?,'Hierarchy migration',0)",
            (self.network,),
        )
        layout_id=connection.execute(
            "SELECT id FROM topology_layouts WHERE name='Hierarchy migration'"
        ).fetchone()['id']
        for name,x in [('Legacy A',-3),('Legacy B',8)]:
            connection.execute(
                """INSERT INTO topology_rooms(layout_id,name,grid_x,grid_y,grid_width,grid_height)
                   VALUES(?,?,?,0,4,4)""",(layout_id,name,x),
            )
        connection.execute(
            """INSERT INTO topology_layout_links(
                   layout_id,source_device_id,target_device_id,relation,properties_json
               ) VALUES(?,?,?,'manual','{"cable":"fiber"}')""",
            (layout_id,self.ids[0],self.ids[1]),
        )
        link_before=tuple(connection.execute(
            'SELECT layout_id,source_device_id,target_device_id,relation,properties_json '
            'FROM topology_layout_links WHERE layout_id=?',(layout_id,),
        ).fetchone())
        connection.execute('DROP TRIGGER topology_rooms_parent_validate_insert')
        connection.execute('DROP TRIGGER topology_rooms_parent_validate_update')
        connection.execute('DROP INDEX idx_topology_rooms_parent')
        connection.execute('ALTER TABLE topology_rooms DROP COLUMN parent_room_id')
        connection.execute('DELETE FROM schema_migrations WHERE version=8')
        connection.execute('PRAGMA user_version=7')
        connection.commit()

        schema.initialize_database(connection)
        schema.initialize_database(connection)
        self.assertEqual(8,connection.execute('PRAGMA user_version').fetchone()[0])
        rooms=connection.execute(
            'SELECT name,parent_room_id FROM topology_rooms WHERE layout_id=? ORDER BY name',(layout_id,),
        ).fetchall()
        self.assertEqual([('Legacy A',None),('Legacy B',None)],[tuple(row) for row in rooms])
        link_after=tuple(connection.execute(
            'SELECT layout_id,source_device_id,target_device_id,relation,properties_json '
            'FROM topology_layout_links WHERE layout_id=?',(layout_id,),
        ).fetchone())
        self.assertEqual(link_before,link_after)
        self.assertEqual([],connection.execute('PRAGMA foreign_key_check').fetchall())
        connection.close()

    def test_api_startup_migrates_old_schema_and_keeps_a_verified_backup(self):
        connection = sqlite3.connect(self.path)
        connection.execute('DROP TABLE topology_layout_links')
        connection.execute('DROP TABLE topology_manual_nodes')
        connection.execute('DELETE FROM schema_migrations WHERE version=6')
        connection.execute('PRAGMA user_version=5')
        connection.commit()
        connection.close()

        async def start_api_and_check_health():
            async with app.router.lifespan_context(app):
                return await asgi_get('http://test/api/health')

        status, body = asyncio.run(start_api_and_check_health())
        self.assertEqual(200, status)
        self.assertEqual('ready', json.loads(body)['database'])

        connection = sqlite3.connect(self.path)
        self.assertEqual(schema.SCHEMA_VERSION,
                         connection.execute('PRAGMA user_version').fetchone()[0])
        connection.close()

        backup_pattern = self.path.name + f'.pre-migration-v5-to-v{schema.SCHEMA_VERSION}-*.bak'
        backups = list(self.path.parent.glob(backup_pattern))
        self.assertEqual(1, len(backups))
        backup = sqlite3.connect(backups[0])
        self.assertEqual(5, backup.execute('PRAGMA user_version').fetchone()[0])
        self.assertIsNone(backup.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='topology_manual_nodes'"
        ).fetchone())
        self.assertEqual('ok', backup.execute('PRAGMA integrity_check').fetchone()[0])
        backup.close()

        # A second worker/reload sees the current schema and does not create a
        # redundant backup or repeat the migration.
        status, body = asyncio.run(start_api_and_check_health())
        self.assertEqual(200, status)
        self.assertEqual('ready', json.loads(body)['database'])
        self.assertEqual(1, len(list(self.path.parent.glob(
            backup_pattern))))

    def test_api_startup_failure_keeps_backup_and_does_not_serve(self):
        connection = sqlite3.connect(self.path)
        connection.execute('DROP TABLE topology_layout_links')
        connection.execute('DROP TABLE topology_manual_nodes')
        connection.execute('DELETE FROM schema_migrations WHERE version=6')
        connection.execute('PRAGMA user_version=5')
        connection.commit()
        connection.close()

        async def start_api():
            async with app.router.lifespan_context(app):
                return None

        with patch('startup_migrations.initialize_database',
                   side_effect=RuntimeError('synthetic migration failure')):
            with self.assertRaisesRegex(RuntimeError, 'transaction was rolled back'):
                asyncio.run(start_api())

        connection = sqlite3.connect(self.path)
        self.assertEqual(5, connection.execute('PRAGMA user_version').fetchone()[0])
        self.assertIsNone(connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='topology_manual_nodes'"
        ).fetchone())
        connection.close()
        self.assertEqual(1, len(list(self.path.parent.glob(
            self.path.name + f'.pre-migration-v5-to-v{schema.SCHEMA_VERSION}-*.bak'))))

    def test_separate_views_and_navigation(self):
        for route, view in [('/', 'list'), ('/list', 'list'), ('/topology', 'topology'), ('/timeline', 'timeline')]:
            status, body = asyncio.run(asgi_get(route))
            self.assertEqual(200, status)
            html = body.decode()
            self.assertIn(f'data-view="{view}"', html)
            self.assertIn(f'href="/{view}" aria-current="page"', html)
            for link in ('/list', '/topology', '/timeline'):
                self.assertIn(f'href="{link}"', html)
            self.assertEqual(view == 'list', 'id="device-table"' in html)
            self.assertEqual(view == 'topology', 'id="topology-graph"' in html)
            self.assertEqual(view == 'timeline', 'id="timeline-content"' in html)
            if view == 'topology':
                self.assertIn('id="topology-room-tool"',html)
                self.assertIn('id="topology-palette"', html)
                palette_start=html.index('id="topology-palette"')
                palette_end=html.index('</div>',palette_start)
                room_tool=html.index('id="topology-room-tool"')
                self.assertLess(palette_start,room_tool)
                self.assertLess(room_tool,palette_end)
                self.assertNotIn('Objekte links auswählen',html)
                self.assertIn('id="topology-context-menu"', html)
                self.assertNotIn('Ausgeblendete Objekte', html)
                self.assertNotIn('topology-hidden-list', html)
                self.assertNotIn('id="topology-manual-create"', html)
                self.assertNotIn('topology-edit-properties', html)
            self.assertNotIn('topology-compare', html)
            self.assertNotIn('topology-before', html)
            self.assertNotIn('topology-snapshot', html)
            if view == 'list':
                self.assertGreater(html.index('id="detail-port-history"'), html.index('id="detail-changes"'))

    def test_topology_editor_uses_palette_and_shared_canvas_interactions(self):
        script = (Path(__file__).parents[1]/'web/static/topology.js').read_text()
        for node_type in ('switch','router','firewall','gateway','access_point',
                          'patchpanel','network','internet','generic'):
            self.assertIn(f"    {node_type}: {{label:",script)
        for interaction in ("addEventListener('pointerdown'", "addEventListener('pointermove'",
                            "addEventListener('contextmenu'", "event.key === 'Escape'",
                            "event.key === 'Delete'", 'getScreenCTM().inverse()',
                            "'DELETE'", "'PUT'", "'POST'", "type:'room-draw'",
                            "type:'room-move'", "type:'room-resize'", 'topologyRoomAtCell',
                            'showTopologyRoomPrompt', 'function clearTopologySelection()',
                            'function topologyDropTargetAtPoint(', 'function setTopologyRoomDropPreview(',
                            "topologyRoomAtCell(gridColumn,gridRow)",
                            "{room_id:room ? Number(room.id) : null,device_id:Number(item.device.id)}",
                            "{room_id:room ? Number(room.id) : null,manual_node_id:Number(item.manual.id)}",
                            "topologyToolMode = 'select'; updateTopologyRoomTool();",
                            "dispatchEvent(new PointerEvent('pointercancel'",
                            "grid_cell_height:Math.round(topologyGridSpacing.row),move_contents:true",
                            'Ungültige Eingabe:'):
            self.assertIn(interaction,script)
        self.assertIn("const gripNames = ['nw','n','ne','e','se','s','sw','w']",script)
        self.assertIn("topologyDropTargetAtPoint(node.x,node.y,reservedSlots)",script)
        self.assertNotIn('renderTopologyManualControls',script)
        self.assertNotIn('Ausblenden',script)
        self.assertIn('for (const manual of (data.layout?.manual_nodes || []))',script)
        self.assertIn('.sort((a,b) => a.bounds.width*a.bounds.height-b.bounds.width*b.bounds.height ||',script)
        self.assertIn("const TOPOLOGY_LABEL_REFERENCE = '333.333.333.333';",script)
        self.assertIn('const TOPOLOGY_HORIZONTAL_GAP = 5;',script)
        self.assertIn('const TOPOLOGY_VERTICAL_GAP = 17;',script)
        self.assertIn('const TOPOLOGY_GRID_ORIGIN = {x:90,y:60};',script)
        self.assertIn('function topologyGridToPixel(gridColumn,gridRow,{nodeAnchor=false}={})',script)
        self.assertIn('function topologyPixelToGrid(x,y,{nodeAnchor=false}={})',script)
        self.assertIn('function topologyGridVectorToPixel(gridColumns,gridRows)',script)
        self.assertIn('function topologyGridSizeToPixel(gridWidth,gridHeight)',script)
        self.assertIn('function topologyGridBoundaryToPixel(gridX,gridY)',script)
        self.assertIn('function topologyPixelToGridBoundary(point)',script)
        self.assertIn('function topologyRoomPixelBounds(room)',script)
        self.assertIn('const measured = measureTopologyCellGeometry(svg);',script)
        self.assertIn('const labelWidth = label.getBBox().width;',script)
        self.assertIn('function fitTopologyNodeLabel(element,fullText,maxWidth)',script)
        self.assertIn("element.textContent = `${characters.slice(0,low).join('')}…`;",script)
        self.assertIn('topologyNodeYOffset',script)
        self.assertIn('function topologyNodePixelBounds(node)',script)
        self.assertIn('node.element.getBBox()',script)
        self.assertIn('row:nodeBounds.height+TOPOLOGY_VERTICAL_GAP,',script)
        self.assertIn('const box = bounds;',script)
        self.assertIn('const roomExtents = topologyRooms.map(topologyRoomPixelBounds);',script)
        self.assertIn('const {width,height}=topologyGridSizeToPixel(Number(room.grid_width),Number(room.grid_height));',script)
        self.assertIn('fitTopologyNodeLabel(label,room.name,Math.max(1,box.width-10));',script)
        self.assertNotIn('TOPOLOGY_ROOM_PADDING',script)
        self.assertNotIn('roomPixelBounds(room,column,row,nodes)',script)
        self.assertIn('const contextChanged = context !== topologyGraphContext;',script)
        self.assertIn("const savedCamera=contextChanged ? readTopologyCamera(context) : null;",script)
        self.assertIn("if (savedCamera) svg.setAttribute('viewBox',savedCamera);",script)
        self.assertIn("else if (!topologyCameraInitialized || !svg.getAttribute('viewBox'))",script)
        self.assertIn('const graphWidth=Math.max(paddedWidth,paddedHeight*aspect);',script)
        self.assertIn('const graphHeight=Math.max(paddedHeight,paddedWidth/aspect);',script)
        self.assertIn('const centerX=(contentLeft+contentRight)/2, centerY=(contentTop+contentBottom)/2;',script)
        self.assertNotIn('Math.max(1000,180+(columns-1)*columnSpacing)',script)
        self.assertIn("topologyGraph.setAttribute('viewBox',topologyBaseViewBox);",script)
        self.assertIn('function readTopologyCamera(networkId)',script)
        self.assertIn('function saveTopologyCamera(svg)',script)
        self.assertIn('saveTopologyCamera(svg);',script)
        self.assertIn('const graphWidth=Math.max(paddedWidth,paddedHeight*aspect);',script)
        self.assertIn('const graphHeight=Math.max(paddedHeight,paddedWidth/aspect);',script)
        self.assertIn('const centerX=(contentLeft+contentRight)/2, centerY=(contentTop+contentBottom)/2;',script)
        self.assertNotIn('Math.max(1000,180+(columns-1)*columnSpacing)',script)
        self.assertNotIn('svg.style.width = `${graphWidth}px`;',script)
        self.assertNotIn('svg.style.height = `${graphHeight}px`;',script)
        self.assertIn("for (const text of ['Erreichbar','Nicht erreichbar','Status unbekannt','Manuell'])",script)
        self.assertIn("label.setAttribute('x',box.x); label.setAttribute('y',box.y-TOPOLOGY_ROOM_TITLE_GAP);",script)
        self.assertNotIn('TOPOLOGY_CONNECTION_CLEARANCE',script)
        self.assertNotIn('const TOPOLOGY_MIN_GRID_WIDTH',script)
        self.assertNotIn("topologyMenuButton('Raum zuordnen'",script)
        self.assertNotIn('function editTopologyRoomAssignment(',script)
        self.assertNotIn('Inhalt beim Raumverschieben mitnehmen',script)
        self.assertIn('const nodes=topologyRenderedNodes.filter(node => node.manual',script)
        self.assertIn('parent_room_id:targetParentId,move_contents:true',script)
        self.assertIn('topologyRoomParentForGridBounds(nextGeometry,state.subtreeIds)',script)
        self.assertIn('for (const child of state.descendantRooms)',script)
        self.assertIn('setTopologyRoomDropPreview(targetParent?.id ?? null)',script)
        self.assertIn('parent_room_id:parentRoomId',script)
        self.assertIn("!event.target.closest?.('.topology-room')",script)
        self.assertIn('syncTopologyRooms(result.rooms);',script)
        self.assertIn('function syncTopologyRooms(updatedRooms)',script)
        self.assertIn('return current ? Object.assign(current,updated) : updated;',script)
        self.assertIn('const currentRoom=topologyRooms.find(item => Number(item.id) === Number(room.id)) || room;',script)
        self.assertIn('moveState={pointerId:event.pointerId,startPoint:point,nodes,room:currentRoom,',script)
        self.assertIn('descendantRooms:descendants,subtreeIds',script)
        self.assertIn('setRoomShape(group,movedRoom,rect,label);',script)
        template=(Path(__file__).parents[1]/'web/templates/index.html').read_text()
        self.assertIn('/static/topology.js?v=canvas-editor-12',template)
        self.assertIn('/static/style.css?v=topology-editor-8',template)
        style=(Path(__file__).parents[1]/'web/static/style.css').read_text()
        self.assertIn('topology-room-drop-target',style)
        self.assertNotIn('.topology-help',style)
        self.assertIn('.topology-viewport { width:100%; height:min(580px,78vh); min-height:280px; overflow:hidden;',style)
        self.assertNotIn('.topology-hidden-panel',style)
        self.assertIn('.topology-viewport #topology-graph { display:block; width:100%; height:100%;',style)
        self.assertNotIn('.topology-viewport { width:100%; overflow:auto;',style)
        topology_html=(Path(__file__).parents[1]/'web/templates/topology.html').read_text()
        self.assertIn('aria-label="Interaktive Netzwerktopologie"',topology_html)
        self.assertIn('connection_points',(Path(__file__).parents[1]/'web/routers/topology.py').read_text())
        self.assertNotIn("#topology-manual-editor",script)

    def test_timeline_midnight_missing_and_explicit_port_close(self):
        connection = sqlite3.connect(self.path)
        connection.execute('DELETE FROM observations')
        device = self.ids[0]
        for observed, kind, data in [
            ('2026-10-10 20:00:00', 'host_discovery', {}),
            ('2026-10-10 21:00:00', 'tcp_port_scan', {'ports': [{'protocol':'tcp', 'port':443, 'state':'open', 'service':'https'}]}),
            ('2026-10-11 00:00:00', 'tcp_port_scan', {'ports': [{'protocol':'tcp', 'port':443, 'state':'closed'}]}),
            ('2026-10-11 04:00:00', 'host_discovery', {})]:
            connection.execute('INSERT INTO observations(network_id,device_id,observation_type,observed_at,data_json) VALUES(?,?,?,?,?)',
                               (self.network, device, kind, observed, json.dumps(data)))
        connection.execute("INSERT INTO changes(network_id,device_id,scan_run_id,change_type,detected_at) VALUES(?,?,1,'DEVICE_MISSING','2026-10-11 02:00:00')", (self.network, device))
        connection.commit(); connection.close()
        status, data = self.request(f'/api/timeline?network_id={self.network}&day=2026-10-11&tz=Europe/Berlin')
        self.assertEqual(200, status)
        row = data['devices'][0]
        self.assertEqual(0, row['intervals'][0]['start'])
        self.assertEqual(240, row['intervals'][0]['end'])
        self.assertEqual(360, row['intervals'][1]['start'])
        self.assertEqual(1440, row['intervals'][1]['end'])
        self.assertEqual(0, row['services'][0]['intervals'][0]['start'])
        self.assertEqual(120, row['services'][0]['intervals'][0]['end'])
        self.assertIn('2026-10-10', data['days'])
        self.assertEqual(422, self.request(f'/api/timeline?network_id={self.network}&tz=invalid')[0])
        self.assertEqual(422, self.request(f'/api/timeline?network_id={self.network}&day=invalid')[0])
        with patch.dict(os.environ, {'NETCHECKER_ALLOWED_SCOPES':'1'}):
            self.assertEqual(404, self.request(f'/api/timeline?network_id={self.other_network}')[0])
        with patch.dict(os.environ, {'NETCHECKER_API_KEY':'test'}):
            self.assertEqual(401, self.request(f'/api/timeline?network_id={self.network}')[0])

    def test_local_lucide_sprite_is_served_without_external_requests(self):
        status,body = asyncio.run(asgi_get('/static/vendor/lucide/sprite.svg'))
        self.assertEqual(200,status)
        self.assertIn(b'id="circle-plus"',body)
        self.assertNotIn(b'<script',body)
