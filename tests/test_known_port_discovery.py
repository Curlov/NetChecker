import contextlib
import io
import json
import sqlite3
import unittest
from unittest.mock import patch

import database
import schema
import scanner
import netchecker_core as core


class KnownPortDiscoveryTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        schema.initialize_database(self.db)
        self.network = database.save_network(self.db,'192.0.2.0/24','test0',None)
        self.run = database.start_scan_run(self.db,self.network,'discovery')
        self.device = database.save_discovery_host(self.db,self.network,self.run,{
            'ip':'192.0.2.10','mac':'00:11:22:33:44:55','hostname':'test-host'})
        database.finish_scan_run(self.db,self.run)

    def tearDown(self):
        self.db.close()

    def store_scan(self, ports, scan_type='detail', observation_type='tcp_port_scan',
                   complete=True, covered=None, infer_os=True):
        run = database.start_scan_run(self.db,self.network,scan_type)
        covered = covered if covered is not None else ','.join(str(p['port']) for p in ports) or '22'
        metadata = {'complete':complete,'scaninfo':[{'protocol':'tcp','services':covered}]}
        database.save_port_scan(self.db,self.network,run,{
            'device_id':self.device,'ip':'192.0.2.10','ports':ports,
            'scan_metadata':metadata},source='synthetic',observation_type=observation_type,
            infer_os=infer_os)
        database.finish_scan_run(self.db,run)
        if observation_type == 'known_tcp_port_scan':
            database.detect_known_port_changes(self.db,self.network,run)
        return run

    def known_scan(self, port, state, complete=True):
        if not complete:
            run = database.start_scan_run(self.db,self.network,'discovery')
            self.db.execute("""INSERT INTO observations(network_id,device_id,scan_run_id,
                observation_type,source,data_json)
                VALUES(?,?,?,'known_tcp_port_scan_attempt','synthetic',?)""",
                (self.network,self.device,run,json.dumps({'requested_ports':[port],
                    'status':'incomplete','scan_metadata':{'complete':False}})))
            database.finish_scan_run(self.db,run)
            database.detect_known_port_changes(self.db,self.network,run)
            return run
        return self.store_scan([{'protocol':'tcp','port':port,'state':state}],
            scan_type='discovery',observation_type='known_tcp_port_scan',
            complete=complete,covered=str(port),infer_os=False)

    def test_open_port_stays_open_and_service_metadata_is_preserved(self):
        self.store_scan([{'protocol':'tcp','port':22,'state':'open','service':'ssh',
                          'product':'OpenSSH','version':'9.0'}])
        self.known_scan(22,'open')
        port = database.get_port_inventory(self.db,self.network,self.device)[0]
        self.assertEqual('open',port['state'])
        self.assertEqual(('ssh','OpenSSH','9.0'),(port['service'],port['product'],port['version']))
        self.assertEqual(0,self.db.execute('SELECT COUNT(*) FROM changes').fetchone()[0])

    def test_close_then_reopen_use_existing_change_history_once(self):
        self.store_scan([{'protocol':'tcp','port':22,'state':'open'}])
        closed_run = self.known_scan(22,'closed')
        self.assertIn(database.get_port_inventory(self.db,self.network,self.device)[0]['state'],
                      ('closed','not_open'))
        self.assertEqual([22],database.get_historically_open_tcp_ports(
            self.db,self.network,self.device))
        self.assertEqual(1,self.db.execute("SELECT COUNT(*) FROM changes WHERE change_type='PORT_NOT_OPEN'").fetchone()[0])
        database.detect_known_port_changes(self.db,self.network,closed_run)
        self.assertEqual(1,self.db.execute("SELECT COUNT(*) FROM changes WHERE change_type='PORT_NOT_OPEN'").fetchone()[0])
        self.known_scan(22,'closed')
        self.assertEqual(1,self.db.execute("SELECT COUNT(*) FROM changes WHERE change_type='PORT_NOT_OPEN'").fetchone()[0])
        self.db.execute('UPDATE port_inventory SET ever_open=0 WHERE network_id=? AND device_id=?',
                        (self.network,self.device))
        schema.migrate_port_inventory_ever_open(self.db)
        self.assertEqual(1,self.db.execute('SELECT ever_open FROM port_inventory WHERE network_id=? AND device_id=?',
                                           (self.network,self.device)).fetchone()[0])
        self.known_scan(22,'open')
        self.assertEqual(1,self.db.execute("SELECT COUNT(*) FROM changes WHERE change_type='PORT_OPENED'").fetchone()[0])

    def test_detail_scan_after_discovery_close_does_not_duplicate_event(self):
        self.store_scan([{'protocol':'tcp','port':22,'state':'open'}])
        self.known_scan(22,'closed')
        self.assertEqual(1,self.db.execute("SELECT COUNT(*) FROM changes WHERE change_type='PORT_NOT_OPEN'").fetchone()[0])
        run = self.store_scan([],scan_type='detail',observation_type='tcp_port_scan',covered='22')
        database.detect_detail_changes(self.db,self.network,run)
        self.assertEqual(1,self.db.execute("SELECT COUNT(*) FROM changes WHERE change_type='PORT_NOT_OPEN'").fetchone()[0])

    def test_filtered_and_incomplete_scans_do_not_close_port(self):
        self.store_scan([{'protocol':'tcp','port':22,'state':'open'}])
        self.known_scan(22,'filtered')
        self.assertEqual(0,self.db.execute('SELECT COUNT(*) FROM changes').fetchone()[0])
        self.assertEqual('filtered',database.get_port_inventory(self.db,self.network,self.device)[0]['state'])
        self.known_scan(22,'closed',complete=False)
        self.assertEqual(0,self.db.execute('SELECT COUNT(*) FROM changes').fetchone()[0])
        self.assertEqual('filtered',database.get_port_inventory(self.db,self.network,self.device)[0]['state'])
        detail = self.store_scan([],scan_type='detail',observation_type='tcp_port_scan',covered='22')
        database.detect_detail_changes(self.db,self.network,detail)
        self.assertEqual('not_open',database.get_port_inventory(self.db,self.network,self.device)[0]['state'])
        self.assertEqual(1,self.db.execute("SELECT COUNT(*) FROM changes WHERE change_type='PORT_NOT_OPEN'").fetchone()[0])

    def test_only_ever_open_ports_are_selected_and_new_details_are_picked_up(self):
        self.store_scan([{'protocol':'tcp','port':22,'state':'open'}],covered='22,80')
        self.store_scan([{'protocol':'tcp','port':80,'state':'open'}],covered='22,80')
        self.assertEqual([22,80],database.get_historically_open_tcp_ports(
            self.db,self.network,self.device))

    def test_device_not_in_discovery_is_not_port_checked(self):
        self.store_scan([{'protocol':'tcp','port':22,'state':'open'}])
        with patch.object(core,'scan_network',return_value=[{'ip':'192.0.2.11','mac':'00:11:22:33:44:66'}]), \
             patch.object(core,'enrich_local_host',side_effect=lambda hosts,interface:hosts), \
             patch.object(core,'get_vendor_from_mac',return_value=None), \
             patch.object(core,'scan_known_tcp_ports') as targeted, \
             contextlib.redirect_stdout(io.StringIO()):
            result = core.run_discovery_cycle(self.db,self.network,
                {'network':'192.0.2.0/24','interface':'test0'})
        self.assertEqual(1,len(result))
        targeted.assert_not_called()
        self.assertEqual('open',database.get_port_inventory(self.db,self.network,self.device)[0]['state'])

    def test_devices_use_their_own_historically_open_port_lists(self):
        self.store_scan([{'protocol':'tcp','port':22,'state':'open'}])
        another_run = database.start_scan_run(self.db,self.network,'discovery')
        other_id = database.save_discovery_host(self.db,self.network,another_run,{
            'ip':'192.0.2.11','mac':'00:11:22:33:44:66','hostname':'other'})
        database.finish_scan_run(self.db,another_run)
        other_detail = database.start_scan_run(self.db,self.network,'detail')
        database.save_port_scan(self.db,self.network,other_detail,{
                'device_id':other_id,'ip':'192.0.2.11',
                'ports':[{'protocol':'tcp','port':443,'state':'open'}],
                'scan_metadata':{'complete':True,'scaninfo':[{'protocol':'tcp','services':'443'}]}},
            source='synthetic')
        database.finish_scan_run(self.db,other_detail)
        hosts = [{'ip':'192.0.2.10','mac':'00:11:22:33:44:55'},
                 {'ip':'192.0.2.11','mac':'00:11:22:33:44:66'}]
        result = lambda port: {'ports':[{'protocol':'tcp','port':port,'state':'open'}],
            'scan_metadata':{'complete':True,'scaninfo':[{'protocol':'tcp','services':str(port)}]}}
        with patch.object(core,'scan_network',return_value=hosts), \
             patch.object(core,'enrich_local_host',side_effect=lambda values,interface:values), \
             patch.object(core,'get_vendor_from_mac',return_value=None), \
             patch.object(core,'scan_known_tcp_ports',side_effect=[result(22),result(443)]) as targeted, \
             contextlib.redirect_stdout(io.StringIO()):
            core.run_discovery_cycle(self.db,self.network,{'network':'192.0.2.0/24','interface':'test0'})
        self.assertEqual([('192.0.2.10',[22]),('192.0.2.11',[443])],
                         [call.args for call in targeted.call_args_list])

    def test_timeout_is_recorded_without_changing_port_or_events(self):
        import subprocess
        self.store_scan([{'protocol':'tcp','port':22,'state':'open'}])
        with patch.object(core,'scan_network',return_value=[{'ip':'192.0.2.10','mac':'00:11:22:33:44:55'}]), \
             patch.object(core,'enrich_local_host',side_effect=lambda hosts,interface:hosts), \
             patch.object(core,'get_vendor_from_mac',return_value=None), \
             patch.object(core,'scan_known_tcp_ports',side_effect=subprocess.TimeoutExpired('nmap',20)), \
             contextlib.redirect_stdout(io.StringIO()):
            core.run_discovery_cycle(self.db,self.network,{'network':'192.0.2.0/24','interface':'test0'})
        self.assertEqual('open',database.get_port_inventory(self.db,self.network,self.device)[0]['state'])
        self.assertEqual(0,self.db.execute('SELECT COUNT(*) FROM changes').fetchone()[0])
        self.assertEqual(1,self.db.execute("SELECT COUNT(*) FROM observations WHERE observation_type='known_tcp_port_scan_attempt'").fetchone()[0])

    def test_nmap_command_is_targeted_and_maps_closed_extraport(self):
        xml = '''<nmaprun><scaninfo type="syn" protocol="tcp" numservices="2" services="22,80"/>
          <host><status state="up"/><ports><port protocol="tcp" portid="22"><state state="open"/></port>
          <extraports state="closed" count="1"><extrareasons reason="conn-refused" count="1" ports="80"/></extraports>
          </ports></host><runstats><finished exit="success"/></runstats></nmaprun>'''
        with patch.object(scanner,'run_nmap',return_value=xml) as execute:
            result = scanner.scan_known_tcp_ports('192.0.2.10',[22,80])
        command = execute.call_args.args[0]
        self.assertEqual(20,execute.call_args.args[1])
        self.assertIn('--host-timeout',command)
        self.assertIn('15s',command)
        self.assertEqual('22,80',command[command.index('-p')+1])
        self.assertNotIn('-sV',command)
        self.assertNotIn('-O',command)
        self.assertNotIn('--script',command)
        self.assertTrue(result['scan_metadata']['complete'])
        self.assertEqual(['open','closed'],[p['state'] for p in result['ports']])

    def test_discovery_targeted_result_does_not_infer_os_claims(self):
        self.store_scan([{'protocol':'tcp','port':22,'state':'open','service':'ssh',
                          'product':'OpenSSH','version':'9.0'}])
        result = {'ports':[{'protocol':'tcp','port':22,'state':'open','service':'wrong-label',
                            'product':'Wrong Product','version':'0.1'}],
                  'os':{'name':'Wrong OS'},
                  'scan_metadata':{'complete':True,'scaninfo':[{'protocol':'tcp','services':'22'}]}}
        with patch.object(core,'scan_network',return_value=[{'ip':'192.0.2.10','mac':'00:11:22:33:44:55'}]), \
             patch.object(core,'enrich_local_host',side_effect=lambda hosts,interface:hosts), \
             patch.object(core,'get_vendor_from_mac',return_value=None), \
             patch.object(core,'scan_known_tcp_ports',return_value=result), \
             contextlib.redirect_stdout(io.StringIO()):
            core.run_discovery_cycle(self.db,self.network,{'network':'192.0.2.0/24','interface':'test0'})
        port = database.get_port_inventory(self.db,self.network,self.device)[0]
        self.assertEqual(('ssh','OpenSSH','9.0'),(port['service'],port['product'],port['version']))
        self.assertEqual(0,self.db.execute('SELECT COUNT(*) FROM os_claims').fetchone()[0])


if __name__ == '__main__':
    unittest.main()
