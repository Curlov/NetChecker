"""Run with python -B -m unittest discover; all databases are synthetic."""
import contextlib
import io
import fcntl
import json
import logging
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock
import xml.etree.ElementTree as ET

import schema
import database
import enrichment
import topology
from transactions import atomic
from runtime_lock import inventory_lock, InventoryBusy
from os_analysis import infer_os_claims, summarize_claims, select_os
from mac_analysis import analyze_mac
from maintenance import backup_database, export_scope
from topology_history import compare_links

logging.getLogger('netchecker').addHandler(logging.NullHandler())


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        schema.initialize_database(self.db)
        self.network = database.save_network(self.db, '192.0.2.0/24', 'test0', None)

    def tearDown(self):
        self.db.close()

    def host(self, mac='00:11:22:33:44:55', ip='192.0.2.10', hostname='test-host', network=None):
        network = network or self.network
        run = database.start_scan_run(self.db, network, 'discovery')
        device = database.save_discovery_host(self.db, network, run, {'ip':ip,'mac':mac,'hostname':hostname})
        database.finish_scan_run(self.db, run)
        return device, run

    def ports(self, device, ports, covered='22', complete=True):
        run = database.start_scan_run(self.db, self.network, 'detail')
        database.save_port_scan(self.db, self.network, run, {'device_id':device,'ip':'192.0.2.10',
            'ports':ports,'scan_metadata':{'complete':complete,'scaninfo':[{'protocol':'tcp','services':covered}]}})
        database.finish_scan_run(self.db, run)
        return run

    def test_schema_idempotent_without_writes(self):
        before = self.db.total_changes
        schema.initialize_database(self.db)
        self.assertEqual(before,self.db.total_changes)
        self.assertEqual([],self.db.execute('PRAGMA foreign_key_check').fetchall())

    def test_port_versions_and_cpe_survive_empty_results(self):
        device,_ = self.host()
        self.ports(device,[{'port':22,'protocol':'tcp','state':'open','service':'ssh','product':'OpenSSH',
                           'version':'9.0','extrainfo':'Ubuntu Linux','cpe':['cpe:/o:canonical:ubuntu_linux:22.04']}])
        self.ports(device,[{'port':22,'protocol':'tcp','state':'open','service':'ssh','version':None}])
        port = database.get_port_inventory(self.db,self.network,device)[0]
        self.assertEqual('9.0',port['version'])
        self.assertEqual('Ubuntu Linux',port['extrainfo'])
        self.assertTrue(port['cpe'])

    def test_changes_can_be_replayed(self):
        device,_ = self.host()
        self.ports(device,[{'port':22,'protocol':'tcp','state':'open'}])
        run = self.ports(device,[])
        database.detect_detail_changes(self.db,self.network,run)
        database.detect_detail_changes(self.db,self.network,run)
        self.assertEqual(1,self.db.execute("SELECT COUNT(*) FROM changes WHERE change_type='PORT_NOT_OPEN'").fetchone()[0])

    def test_uncovered_ports_not_closed(self):
        device,_ = self.host()
        self.ports(device,[{'port':22,'protocol':'tcp','state':'open'}])
        self.ports(device,[],covered='80')
        self.assertEqual('open',database.get_port_inventory(self.db,self.network,device)[0]['state'])
        self.ports(device,[],complete=False)
        self.assertEqual('open',database.get_port_inventory(self.db,self.network,device)[0]['state'])

    def test_partial_discovery_does_not_increment_misses(self):
        device,run = self.host()
        database.detect_discovery_changes(self.db,self.network,run)
        for _ in range(2):
            failed = database.start_scan_run(self.db,self.network,'discovery')
            database.finish_scan_run(self.db,failed,hosts_failed=1)
            database.detect_discovery_changes(self.db,self.network,failed)
        state = self.db.execute('SELECT * FROM device_presence WHERE device_id=?',(device,)).fetchone()
        self.assertEqual('present',state['state'])
        self.assertEqual(0,state['consecutive_misses'])

    def test_discovery_comparison_can_be_replayed(self):
        device,run = self.host()
        database.detect_discovery_changes(self.db,self.network,run)
        missing = database.start_scan_run(self.db,self.network,'discovery')
        database.finish_scan_run(self.db,missing)
        database.detect_discovery_changes(self.db,self.network,missing)
        database.detect_discovery_changes(self.db,self.network,missing)
        state = self.db.execute('SELECT * FROM device_presence WHERE device_id=?',(device,)).fetchone()
        self.assertEqual(1,state['consecutive_misses'])
        self.assertEqual('present',state['state'])

    def test_nested_failure_rolls_back_enrichment(self):
        device,run = self.host()
        result = {'status':'success','ports':[{'port':22,'protocol':'tcp','state':'open'}]}
        with patch('enrichment.save_os_claims',side_effect=RuntimeError('synthetic failure')):
            with self.assertRaises(RuntimeError):
                enrichment.persist_enrichment_result(self.db,self.network,run,{'id':device},result,'light')
        self.assertEqual([],database.get_port_inventory(self.db,self.network,device))
        self.assertEqual(0,self.db.execute("SELECT COUNT(*) FROM observations WHERE observation_type='service_scan'").fetchone()[0])

    def test_mac_upgrade_does_not_merge_without_evidence(self):
        provisional,_ = self.host(mac=None)
        confirmed,_ = self.host()
        self.assertNotEqual(provisional,confirmed)
        self.assertEqual(1,self.db.execute('SELECT COUNT(*) FROM identity_candidates').fetchone()[0])

    def test_mac_identity_survives_ip_change(self):
        old,_ = self.host()
        new,_ = self.host(ip='192.0.2.20')
        self.assertEqual(old,new)

    def test_local_anchor_survives_mac_change(self):
        run = database.start_scan_run(self.db,self.network,'discovery')
        old = database.save_discovery_host(self.db,self.network,run,
            {'ip':'192.0.2.10','mac':'00:11:22:33:44:55','local_identity_key':'synthetic-local'})
        new = database.save_discovery_host(self.db,self.network,run,
            {'ip':'192.0.2.20','mac':'00:11:22:33:44:66','local_identity_key':'synthetic-local'})
        self.assertEqual(old,new)
        self.assertEqual(2,self.db.execute('SELECT COUNT(*) FROM device_interfaces').fetchone()[0])

    def second_scope(self):
        self.db.execute("INSERT INTO network_scopes(id,name,customer,site) VALUES(2,'test','customer2','site')")
        self.db.commit()
        return database.save_network(self.db,'192.0.2.0/24','test0',None,scope_id=2)

    def test_scope_identity_candidates_do_not_cross_customers(self):
        second = self.second_scope()
        device,_ = self.host(network=second)
        snapshot = topology.create_snapshot(self.db,self.network,'test0',None)
        topology.derive_identity_candidates(self.db,snapshot,{'dhcp_lease':[
            {'address':'192.0.2.20','mac-address':'00:11:22:33:44:66','host-name':'test-host'}]})
        self.assertEqual(0,self.db.execute('SELECT COUNT(*) FROM topology_identity_candidates').fetchone()[0])

    def test_mac_lookup_uses_explicit_scope(self):
        second = self.second_scope()
        first,_ = self.host()
        other,_ = self.host(network=second)
        self.assertNotEqual(first,other)
        self.assertEqual(other,topology.find_device_id_by_mac(self.db,'00:11:22:33:44:55',second))

    def test_backfill_includes_service_metadata(self):
        device,run = self.host()
        payload = {'ports':[{'port':22,'protocol':'tcp','state':'open','service':'ssh',
            'version':'9.0','extrainfo':'Debian 12','cpe':['cpe:/o:debian:debian_linux:12'],
            'service_metadata':{'method':'probed'}}]}
        self.db.execute("INSERT INTO observations(network_id,device_id,scan_run_id,observation_type,data_json) VALUES(?,?,?,'service_scan',?)",
                        (self.network,device,run,json.dumps(payload)))
        self.db.commit()
        schema.backfill_service_inventory(self.db)
        port = database.get_port_inventory(self.db,self.network,device)[0]
        self.assertEqual('Debian 12',port['extrainfo'])
        self.assertEqual({'method':'probed'},port['service_metadata'])
        count = self.db.execute('SELECT COUNT(*) FROM os_claims').fetchone()[0]
        schema.backfill_service_inventory(self.db)
        self.assertEqual(count,self.db.execute('SELECT COUNT(*) FROM os_claims').fetchone()[0])

    def test_backfill_does_not_reopen_a_newer_negative_scan(self):
        device,_ = self.host()
        self.ports(device,[{'port':22,'protocol':'tcp','state':'open','version':'9.0'}])
        self.ports(device,[])
        schema.backfill_service_inventory(self.db)
        port = database.get_port_inventory(self.db,self.network,device)[0]
        self.assertEqual('not_open',port['state'])
        self.assertEqual('9.0',port['version'])

    def test_backfill_fills_older_metadata_without_downgrade(self):
        device,run = self.host()
        old = {'ports':[{'port':22,'protocol':'tcp','state':'open','version':'8.0','extrainfo':'Debian 12'}]}
        self.db.execute("INSERT INTO observations(network_id,device_id,scan_run_id,observation_type,data_json) VALUES(?,?,?,'service_scan',?)",
                        (self.network,device,run,json.dumps(old)))
        self.db.commit()
        self.ports(device,[{'port':22,'protocol':'tcp','state':'open','version':'9.0'}])
        schema.backfill_service_inventory(self.db)
        port = database.get_port_inventory(self.db,self.network,device)[0]
        self.assertEqual('9.0',port['version'])
        self.assertEqual('Debian 12',port['extrainfo'])

    def test_os_claims_keep_history_but_project_latest_evidence(self):
        device,run = self.host()
        claim = dict(kind='family',value='Linux',source='synthetic',status='suspected',confidence=70,evidence={})
        with atomic(self.db): database.save_os_claims(self.db,self.network,run,device,[claim])
        other = database.start_scan_run(self.db,self.network,'detail')
        with atomic(self.db): database.save_os_claims(self.db,self.network,other,device,[claim])
        self.assertEqual(2,self.db.execute('SELECT COUNT(*) FROM os_claims').fetchone()[0])
        self.assertEqual(1,len(database.get_os_claims(self.db,self.network,device)))

    def test_station_only_is_not_switch_even_with_switch_word(self):
        self.assertFalse(topology._neighbor_is_infrastructure({'system-caps-enabled':'station-only',
            'system-description':'workstation with virtual switch'}))

    def test_scope_export_isolated_and_exclusive(self):
        second = self.second_scope()
        first,_ = self.host()
        other,_ = self.host(network=second,hostname='private-other-customer')
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/'source.db'
            target = sqlite3.connect(source)
            self.db.backup(target); target.close()
            output = Path(directory)/'scope.jsonl'
            export_scope(source,output,1)
            content = output.read_text()
            self.assertNotIn('private-other-customer',content)
            with self.assertRaises(FileExistsError):
                export_scope(source,output,1)
            self.assertEqual(content,output.read_text())
            backup = Path(directory)/'backup.db'
            backup_database(source,backup)
            self.assertEqual(0o600,backup.stat().st_mode & 0o777)


class PureTest(unittest.TestCase):
    def test_mac_facts(self):
        mac = analyze_mac('CE:48:79:29:0A:BA')
        self.assertTrue(mac['unicast']); self.assertTrue(mac['locally_administered'])
        self.assertFalse(analyze_mac('garbage')['valid'])

    def test_parser_retains_services_with_fingerprint(self):
        xml = '<nmaprun><scaninfo protocol="tcp" services="22"/><host><status state="up"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" extrainfo="Ubuntu 22.04 Linux"/></port></ports><os><osmatch name="Linux 6.x" accuracy="95"/></os></host><runstats><finished exit="success"/></runstats></nmaprun>'
        with patch('enrichment.ET.parse',return_value=ET.ElementTree(ET.fromstring(xml))):
            result = enrichment.parse_scan_xml('synthetic')
        claims = infer_os_claims(result['os'],result['ports'])
        self.assertTrue(any(c['kind']=='distribution' and c['value']=='Ubuntu' for c in claims))
        self.assertTrue(any(c['kind']=='distribution_version' for c in claims))

    def test_kernel_not_distribution_or_ssh_version(self):
        claims = infer_os_claims({'name':'Linux 6.x','source':'nmap_os','accuracy':95})
        self.assertFalse(any(c['kind']=='distribution' for c in claims))
        claims = infer_os_claims(ports=[{'port':22,'state':'open','version':'9.0','product':'OpenSSH'}])
        self.assertFalse(any(c['kind']=='kernel' for c in claims))

    def test_cpe_kernel_and_scripts(self):
        claims = infer_os_claims(ports=[{'port':22,'state':'open','cpe':['cpe:/o:linux:linux_kernel:6.1'],
            'scripts':[{'id':'banner','output':'Debian 12'}]}])
        self.assertTrue(any(c['kind']=='kernel' and c['value']=='6.1' for c in claims))
        self.assertTrue(any(c['kind']=='distribution' and c['value']=='Debian' for c in claims))

    def test_os_installation_can_change(self):
        self.assertEqual('new',select_os([{'name':'old','accuracy':99,'observed_at':'2020-01-01'},
            {'name':'new','accuracy':90,'observed_at':'2026-01-01'}])['name'])
        summary = summarize_claims([{'kind':'family','value':'Linux','status':'confirmed','confidence':100,'observed_at':'2020-01-01'},
            {'kind':'family','value':'Windows','status':'suspected','confidence':90,'observed_at':'2999-01-01'}])
        self.assertEqual('Windows',summary['family']['value'])
        self.assertTrue(summary['family']['conflicting'])

    def test_topology_diff_ignores_row_ids(self):
        old = {'id':1,'source_ip':'192.0.2.1','target_ip':'192.0.2.2','relation':'arp_binding','confidence':90}
        new = dict(old,id=10)
        self.assertEqual([],compare_links([old],[new])['changed'])
        self.assertEqual(1,len(compare_links([old],[])['removed']))

    def test_launcher_does_not_suspend_core(self):
        import netchecker
        core = Mock(); core.poll.return_value = None
        with patch('netchecker.scan_is_running',return_value=False), patch('netchecker.run_classification_reconcile',return_value=75):
            self.assertFalse(netchecker.run_serial_classification_reconcile(core))
        core.send_signal.assert_not_called()

    def test_lock_cross_process_and_reentrant(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory)/'inventory.db'
            env = dict(os.environ,NETCHECKER_DATABASE=str(database_path))
            code = 'from runtime_lock import inventory_lock, InventoryBusy\ntry:\n with inventory_lock(nonblocking=True): pass\nexcept InventoryBusy: raise SystemExit(75)'
            with inventory_lock(database_path=database_path):
                with inventory_lock(database_path=database_path):
                    result = subprocess.run([sys.executable,'-B','-c',code],env=env,timeout=5)
                    self.assertEqual(75,result.returncode)
            self.assertEqual(0,subprocess.run([sys.executable,'-B','-c',code],env=env,timeout=5).returncode)

    def test_second_scanner_is_rejected_before_its_body(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'inventory.db'
            code = 'from runtime_lock import single_scanner, InventoryBusy\n@single_scanner\ndef main(): pass\ntry: main()\nexcept InventoryBusy: raise SystemExit(75)'
            env = dict(os.environ,NETCHECKER_DATABASE=str(path))
            with path.with_suffix('.scanner.lock').open('a') as handle:
                fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
                self.assertEqual(75,subprocess.run([sys.executable,'-B','-c',code],env=env,timeout=5).returncode)
            self.assertEqual(0,subprocess.run([sys.executable,'-B','-c',code],env=env,timeout=5).returncode)


class PipelineTest(unittest.TestCase):
    setUp = InventoryTest.setUp
    tearDown = InventoryTest.tearDown

    def test_synthetic_pipeline_does_not_execute_external_commands(self):
        import netchecker_core as core
        import runtime_lock
        host = {'ip':'192.0.2.10','mac':'00:11:22:33:44:55','hostname':'synthetic-host'}
        details = {'ports':[{'protocol':'tcp','port':22,'state':'open'}],
                   'scan_metadata':{'complete':True,'scaninfo':[{'protocol':'tcp','services':'22'}]},'os':None}
        enriched = dict(details,os={'name':'Linux 6.x','accuracy':95,'source':'nmap_os'})
        enriched['ports'] = [{'protocol':'tcp','port':22,'state':'open','product':'OpenSSH','extrainfo':'Ubuntu 22.04 Linux'}]
        enriched['status'] = 'success'
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(runtime_lock,'DATABASE_PATH',Path(directory)/'synthetic.db'))
            stack.enter_context(patch('subprocess.run',side_effect=AssertionError('Unexpected external command')))
            stack.enter_context(patch.object(core,'scan_network',return_value=[host]))
            stack.enter_context(patch.object(core,'enrich_local_host',side_effect=lambda hosts,interface:hosts))
            stack.enter_context(patch.object(core,'get_vendor_from_mac',return_value=None))
            stack.enter_context(patch.object(core,'scan_host_details',return_value=details))
            stack.enter_context(patch.object(enrichment,'check_reachability',return_value={'status':'reachable'}))
            light = stack.enter_context(patch.object(enrichment,'scan_light',return_value=enriched))
            deep = stack.enter_context(patch.object(enrichment,'scan_deep',side_effect=AssertionError('Unnecessary DEEP')))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            hosts = core.run_discovery_cycle(self.db,self.network,{'network':'192.0.2.0/24','interface':'test0'})
            self.assertTrue(core.run_detail_cycle(self.db,self.network,hosts))
            core.run_classification_cycle(self.db,self.network,'synthetic')
            self.assertTrue(core.run_enrichment_cycle(self.db,self.network))
            core.run_classification_cycle(self.db,self.network,'synthetic enriched')
            self.assertFalse(core.run_enrichment_cycle(self.db,self.network))
            light.assert_called_once(); deep.assert_not_called()
        self.assertEqual('os_found',self.db.execute('SELECT status FROM enrichment_status').fetchone()[0])
        self.assertTrue(any(claim['value']=='Ubuntu' for claim in database.get_os_claims(self.db,self.network,host['device_id'])))


class MigrationTest(unittest.TestCase):
    def test_version_three_migration_preserves_existing_inventory(self):
        connection = sqlite3.connect(':memory:'); connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA foreign_keys=ON'); schema.initialize_database(connection)
        network = database.save_network(connection,'192.0.2.0/24','test0',None)
        run = database.start_scan_run(connection,network,'discovery')
        device = database.save_discovery_host(connection,network,run,{'ip':'192.0.2.2','mac':'00:11:22:33:44:55'})
        before = connection.execute('SELECT COUNT(*) FROM observations').fetchone()[0]
        connection.execute('DROP TABLE schema_migrations'); connection.execute('PRAGMA user_version=3'); connection.commit()
        schema.initialize_database(connection)
        self.assertEqual(schema.SCHEMA_VERSION,connection.execute('PRAGMA user_version').fetchone()[0])
        self.assertEqual(device,connection.execute('SELECT id FROM devices').fetchone()[0])
        self.assertEqual(before,connection.execute('SELECT COUNT(*) FROM observations').fetchone()[0])
        self.assertEqual([],connection.execute('PRAGMA foreign_key_check').fetchall())
        self.assertEqual(4,connection.execute('SELECT version FROM schema_migrations').fetchone()[0])
        connection.close()

    def test_rollback_on_failed_migration(self):
        connection = sqlite3.connect(':memory:'); connection.row_factory = sqlite3.Row
        with patch('schema.backfill_service_inventory',side_effect=RuntimeError('synthetic')):
            with self.assertRaises(RuntimeError): schema.initialize_database(connection)
        self.assertEqual(0,connection.execute('PRAGMA user_version').fetchone()[0])
        self.assertEqual(0,connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0])
        connection.close()

    def test_legacy_ids_indexes_and_triggers_survive(self):
        connection = sqlite3.connect(':memory:'); connection.row_factory = sqlite3.Row
        schema._init_base_tables(connection)
        connection.execute("INSERT INTO devices(id,mac) VALUES(42,'00:11:22:33:44:55')")
        connection.execute('CREATE INDEX test_hostname ON devices(hostname)')
        connection.execute('CREATE TABLE audit (device_id INTEGER)')
        connection.execute('CREATE TRIGGER test_device AFTER INSERT ON devices BEGIN INSERT INTO audit VALUES(NEW.id); END')
        connection.commit()
        schema.initialize_database(connection)
        self.assertEqual(42,connection.execute('SELECT id FROM devices').fetchone()[0])
        self.assertIsNotNone(connection.execute("SELECT 1 FROM sqlite_master WHERE name='test_hostname'").fetchone())
        connection.execute("INSERT INTO devices(scope_id,mac) VALUES(1,'00:11:22:33:44:66')")
        self.assertEqual(43,connection.execute('SELECT device_id FROM audit').fetchone()[0])
        connection.close()


if __name__ == '__main__':
    unittest.main()
