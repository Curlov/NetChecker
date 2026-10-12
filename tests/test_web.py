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


async def asgi_get(url, headers=()):
    parsed = urlsplit(url)
    events = []
    request_sent = False

    async def receive():
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {'type':'http.request','body':b'','more_body':False}
        await asyncio.Event().wait()

    async def send(message):
        events.append(message)

    await app({'type':'http','asgi':{'version':'3.0','spec_version':'2.4'},'http_version':'1.1',
        'method':'GET','scheme':'http','path':parsed.path,'raw_path':parsed.path.encode(),
        'query_string':parsed.query.encode(),'root_path':'','headers':list(headers),
        'server':('synthetic',8000),'client':('synthetic',1)},receive,send)
    status = next(event['status'] for event in events if event['type']=='http.response.start')
    body = b''.join(event.get('body',b'') for event in events if event['type']=='http.response.body')
    return status, body


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

    def test_unmigrated_schema_returns_503(self):
        connection = sqlite3.connect(self.path); connection.execute('PRAGMA user_version=3'); connection.close()
        self.assertEqual(503,self.request('/api/health')[0])

    def test_html_and_static_ids_match(self):
        import re
        html = Path('web/templates/index.html').read_text()
        js = Path('web/static/app.js').read_text()
        selectors = re.findall(r"querySelector\(['\"]#([\w-]+)['\"]\)",js)
        for selector in selectors:
            self.assertRegex(html, 'id="'+re.escape(selector)+'"')
        status,body = asyncio.run(asgi_get('/'))
        self.assertEqual(200,status)
        self.assertIn(b'topology-graph',body)

    def test_local_lucide_sprite_is_served_without_external_requests(self):
        status,body = asyncio.run(asgi_get('/static/vendor/lucide/sprite.svg'))
        self.assertEqual(200,status)
        self.assertIn(b'id="circle-plus"',body)
        self.assertNotIn(b'<script',body)
