"""RDP NTLM enrichment uses stored Nmap XML fixtures and never scans a live host."""
import contextlib
import io
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import database
import enrichment
import schema
from transactions import atomic
from tests import test_offline as fixtures


RDP_XML = '''<?xml version="1.0"?>
<nmaprun>
  <host><status state="up" />
    <address addr="192.0.2.10" addrtype="ipv4" />
    <ports><port protocol="tcp" portid="3389"><state state="open" />
      <script id="rdp-ntlm-info" output="NTLM info">
        <table>
          <elem key="Target_Name">BARUCOM</elem>
          <elem key="NetBIOS_Domain_Name">BARUCOM</elem>
          <elem key="NetBIOS_Computer_Name">BC-CEO</elem>
          <elem key="DNS_Domain_Name">barucom.local</elem>
          <elem key="DNS_Computer_Name">BC-CEO.barucom.local</elem>
          <elem key="DNS_Tree_Name">barucom.local</elem>
          <elem key="Product_Version">10.0.26100</elem>
        </table>
      </script>
    </port></ports>
  </host>
</nmaprun>'''


class RdpEnrichmentTest(unittest.TestCase):
    setUp = fixtures.InventoryTest.setUp
    tearDown = fixtures.InventoryTest.tearDown
    host = fixtures.InventoryTest.host
    ports = fixtures.InventoryTest.ports

    def prepared(self, number=10, os_known=True):
        ip = f'192.0.2.{number}'
        device, run = self.host(ip=ip, mac=f'00:11:22:33:44:{number:02X}')
        with atomic(self.db):
            database.set_device_present(self.db, self.network, device, run)
        self.ports(device, [{'protocol': 'tcp', 'port': 3389, 'state': 'open', 'service': 'ms-wbt-server'}])
        if os_known:
            database.save_os_information(self.db, self.network, run, {
                'device_id': device, 'ip': ip,
                'os': {'name': 'Microsoft Windows Server 2022', 'accuracy': 92, 'source': 'nmap_os'},
            })
        return device

    def write_xml_result(self, content=RDP_XML, returncode=0):
        def run(command, **kwargs):
            xml_path = command[command.index('-oX') + 1]
            Path(xml_path).write_text(content, encoding='utf-8')
            return Mock(returncode=returncode, stderr='')
        return run

    def test_successful_xml_probe_saves_build_and_names_to_existing_device(self):
        device = self.prepared()
        selected = database.get_inventory(self.db, device, network_id=self.network)[0]
        with patch('enrichment.subprocess.run', side_effect=self.write_xml_result()) as run_nmap:
            result = enrichment.scan_rdp_ntlm_info(selected)
        command = run_nmap.call_args.args[0]
        self.assertEqual('3389', command[command.index('-p') + 1])
        self.assertEqual('rdp-ntlm-info', command[command.index('--script') + 1])
        self.assertEqual(selected['ip'], command[-1])
        self.assertEqual('success', result['status'])
        self.assertEqual({'major': 10, 'minor': 0, 'build': 26100}, result['version'])
        self.assertEqual('BC-CEO', result['fields']['NetBIOS_Computer_Name'])

        run_id = database.start_scan_run(self.db, self.network, 'enrichment')
        with patch('enrichment.scan_rdp_ntlm_info', return_value=result):
            persisted = enrichment.enrich_rdp_ntlm_info(self.db, self.network, run_id, selected)
        saved = database.get_rdp_ntlm_info(self.db, self.network, device)
        self.assertTrue(persisted['success'])
        self.assertEqual('10.0.26100', saved['product_version'])
        self.assertIsNone(saved['edition'])
        self.assertEqual('Windows', saved['family'])
        self.assertEqual(device, self.db.execute(
            "SELECT device_id FROM observations WHERE observation_type='rdp_ntlm_info'"
        ).fetchone()['device_id'])
        claim = self.db.execute("SELECT kind,value,source,status FROM os_claims WHERE source='rdp_ntlm_info'").fetchone()
        self.assertEqual(('version', '10.0.26100', 'rdp_ntlm_info', 'suspected'), tuple(claim))
        self.assertEqual('Microsoft Windows Server 2022', database.get_os_history(
            self.db, self.network, device)[0]['name'])

    def test_missing_build_keeps_other_structured_fields(self):
        xml = RDP_XML.replace('<elem key="Product_Version">10.0.26100</elem>', '')
        device = {'ip': '192.0.2.10', 'ports': [{'protocol': 'tcp', 'port': 3389, 'state': 'open'}]}
        with patch('enrichment.subprocess.run', side_effect=self.write_xml_result(xml)):
            result = enrichment.scan_rdp_ntlm_info(device)
        self.assertEqual('success', result['status'])
        self.assertIsNone(result['product_version'])
        self.assertIsNone(result['version'])
        self.assertEqual('BARUCOM', result['fields']['NetBIOS_Domain_Name'])

    def test_no_script_data_unreachable_and_malformed_xml_are_handled(self):
        device = {'ip': '192.0.2.10', 'ports': [{'protocol': 'tcp', 'port': 3389, 'state': 'open'}]}
        no_script = '<nmaprun><host><ports><port protocol="tcp" portid="3389"><state state="open" /></port></ports></host></nmaprun>'
        with patch('enrichment.subprocess.run', side_effect=self.write_xml_result(no_script)):
            self.assertEqual('no_data', enrichment.scan_rdp_ntlm_info(device)['status'])
        with patch('enrichment.subprocess.run', side_effect=self.write_xml_result('<nmaprun><host>')):
            self.assertEqual('parse_error', enrichment.scan_rdp_ntlm_info(device)['status'])
        with patch('enrichment.subprocess.run', side_effect=self.write_xml_result(returncode=1)):
            self.assertEqual('nmap_error', enrichment.scan_rdp_ntlm_info(device)['status'])
        with patch('enrichment.subprocess.run', side_effect=subprocess.TimeoutExpired('nmap', 1)):
            self.assertEqual('timeout', enrichment.scan_rdp_ntlm_info(device)['status'])

    def test_only_known_open_tcp_3389_is_eligible(self):
        for device in (
            {'ip': '192.0.2.10', 'ports': [{'protocol': 'tcp', 'port': 3389, 'state': 'closed'}]},
            {'ip': '192.0.2.10', 'ports': [{'protocol': 'udp', 'port': 3389, 'state': 'open'}]},
        ):
            with patch('enrichment.subprocess.run', side_effect=AssertionError('Nmap must not run')):
                self.assertEqual('skipped', enrichment.scan_rdp_ntlm_info(device)['status'])

    def test_selected_independently_and_cached_without_os_scan_or_duplicate(self):
        device = self.prepared(os_known=True)
        env = {'NETCHECKER_RDP_MAX_HOSTS': '4', 'NETCHECKER_SERVICE_MAX_HOSTS': '0'}
        with patch.dict(os.environ, env):
            targets, stats = enrichment.get_enrichment_targets(self.db, self.network)
        self.assertEqual(1, stats['rdp_targets'])
        self.assertEqual('rdp_ntlm_info', targets[0][0]['_enrichment_goal'])
        result = {
            'status': 'success', 'fields': {'Product_Version': '10.0.26100'},
            'family': 'Windows', 'product_version': '10.0.26100',
            'version': {'major': 10, 'minor': 0, 'build': 26100}, 'edition': None,
        }
        with patch.dict(os.environ, env), patch('enrichment.scan_rdp_ntlm_info', return_value=result), \
             patch('enrichment.enrich_device', side_effect=AssertionError('No OS scan')), \
             contextlib.redirect_stdout(io.StringIO()):
            enrichment.run_enrichment(self.db, self.network, targets)
            count = self.db.execute("SELECT COUNT(*) FROM observations WHERE observation_type='rdp_ntlm_info'").fetchone()[0]
            changes_before_reselection = self.db.total_changes
            selected_again, stats_again = enrichment.get_enrichment_targets(self.db, self.network)
        self.assertEqual(1, count)
        self.assertEqual([], selected_again)
        self.assertEqual(0, stats_again['rdp_targets'])
        self.assertEqual(changes_before_reselection, self.db.total_changes)
        self.assertEqual('Microsoft Windows Server 2022', database.get_os_history(
            self.db, self.network, device)[0]['name'])
        self.assertEqual(26100, database.get_rdp_ntlm_info(
            self.db, self.network, device)['version']['build'])

    def test_rdp_host_budget_defers_excess_devices(self):
        for number in (10, 11, 12):
            self.prepared(number)
        with patch.dict(os.environ, {'NETCHECKER_RDP_MAX_HOSTS': '1',
                                     'NETCHECKER_SERVICE_MAX_HOSTS': '0'}):
            targets, stats = enrichment.get_enrichment_targets(self.db, self.network)
        self.assertEqual(1, stats['rdp_targets'])
        self.assertEqual(2, stats['rdp_deferred'])
        self.assertEqual(1, len(targets))
        self.assertEqual('rdp_ntlm_info', targets[0][0]['_enrichment_goal'])

    def test_failed_attempt_preserves_last_success_and_uses_retry_cooldown(self):
        device = self.prepared()
        selected = database.get_inventory(self.db, device, network_id=self.network)[0]
        run_id = database.start_scan_run(self.db, self.network, 'enrichment')
        success = {'status': 'success', 'fields': {'Product_Version': '10.0.26100'},
                   'family': 'Windows', 'product_version': '10.0.26100',
                   'version': {'major': 10, 'minor': 0, 'build': 26100}, 'edition': None}
        with patch('enrichment.scan_rdp_ntlm_info', return_value=success):
            enrichment.enrich_rdp_ntlm_info(self.db, self.network, run_id, selected)
        with patch('enrichment.scan_rdp_ntlm_info', return_value={'status': 'timeout', 'fields': {}}):
            enrichment.enrich_rdp_ntlm_info(self.db, self.network, run_id, selected)
        saved = database.get_rdp_ntlm_info(self.db, self.network, device)
        self.assertEqual('10.0.26100', saved['product_version'])
        due, _ = enrichment.rdp_ntlm_info_due(self.db, self.network, selected)
        self.assertFalse(due)
        self.db.execute("UPDATE observations SET observed_at=datetime('now','-2 hours') WHERE observation_type='rdp_ntlm_info_attempt'")
        self.db.commit()
        self.assertTrue(enrichment.rdp_ntlm_info_due(self.db, self.network, selected)[0])

    def test_successful_observation_survives_database_reopen(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / 'rdp.db'
        connection = sqlite3.connect(path)
        connection.row_factory = sqlite3.Row
        schema.initialize_database(connection)
        network = database.save_network(connection, '198.51.100.0/24', 'test1', None)
        run_id = database.start_scan_run(connection, network, 'discovery')
        device = database.save_discovery_host(connection, network, run_id,
            {'ip': '198.51.100.10', 'mac': '00:11:22:33:44:99'})
        database.finish_scan_run(connection, run_id)
        enrichment_run = database.start_scan_run(connection, network, 'enrichment')
        result = {'status': 'success', 'fields': {'Product_Version': '10.0.26100'},
                  'family': 'Windows', 'product_version': '10.0.26100',
                  'version': {'major': 10, 'minor': 0, 'build': 26100}, 'edition': None}
        with patch('enrichment.scan_rdp_ntlm_info', return_value=result):
            enrichment.enrich_rdp_ntlm_info(connection, network, enrichment_run,
                {'id': device, 'ip': '198.51.100.10'})
        database.finish_scan_run(connection, enrichment_run)
        connection.close()
        reopened = sqlite3.connect(path)
        reopened.row_factory = sqlite3.Row
        self.assertEqual('10.0.26100', database.get_rdp_ntlm_info(reopened, network, device)['product_version'])
        reopened.close()


if __name__ == '__main__':
    unittest.main()
