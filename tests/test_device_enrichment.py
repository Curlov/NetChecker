"""Samsung device enrichment is exercised with synthetic HTTP responses."""
import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import database
import device_enrichment
import enrichment
from classification_store import classify_and_store_inventory, save_classification
from classifier import classify_device
from transactions import atomic
from tests import test_offline as fixtures


class SamsungSmartTVEnrichmentTest(unittest.TestCase):
    setUp = fixtures.InventoryTest.setUp
    tearDown = fixtures.InventoryTest.tearDown
    host = fixtures.InventoryTest.host
    ports = fixtures.InventoryTest.ports

    def samsung(self, number=10):
        ip = f'192.0.2.{number}'
        device_id, run_id = self.host(
            mac=f'00:11:22:33:44:{number:02X}', ip=ip, hostname='television'
        )
        self.db.execute("UPDATE devices SET vendor='Samsung Electronics Co., Ltd.' WHERE id=?",
                        (device_id,))
        self.db.execute("UPDATE devices SET display_name='Wohnzimmer-TV' WHERE id=?",
                        (device_id,))
        self.db.commit()
        with atomic(self.db):
            database.set_device_present(self.db, self.network, device_id, run_id)
        self.ports(device_id, [{'protocol':'tcp','port':8001,'state':'open'}], covered='8001')
        return device_id, ip

    @staticmethod
    def api_payload(device_type='Samsung SmartTV'):
        return json.dumps({'device': {
            'type': device_type,
            'name': 'Samsung AU7179 75 TV',
            'modelName': 'GU75AU7179UXZG',
            'OS': 'Tizen',
            'networkType': 'wireless',
        }}).encode()

    def test_only_samsung_vendor_with_open_tcp_8001_matches(self):
        device = {'vendor':'Samsung Electronics', 'ip':'192.0.2.10', 'ports':[
            {'protocol':'tcp','port':8001,'state':'open'}]}
        self.assertTrue(device_enrichment.matching_enrichers(device))
        for overrides in (
            {'vendor':'Unknown'},
            {'ports':[{'protocol':'tcp','port':8001,'state':'closed'}]},
            {'ports':[{'protocol':'udp','port':8001,'state':'open'}]},
        ):
            candidate = dict(device, **overrides)
            self.assertFalse(device_enrichment.matching_enrichers(candidate))

    def test_automatic_probe_persists_confirmed_facts_and_classifies_tv(self):
        device_id, ip = self.samsung()
        targets, stats = enrichment.get_enrichment_targets(self.db, self.network)
        target = next(device for device, _ in targets if device['id'] == device_id)
        self.assertEqual(1, stats['device_targets'])
        self.assertIn('samsung_smart_tv_api', target['_device_enrichers'])

        with patch('enrichment.enrich_services', return_value={
                'success':True,'technical_error':False,'temporary_unreachable':False,
                'timeout':False,'stage':'service_light','os':None}), \
             patch('device_enrichment.urlopen', return_value=io.BytesIO(self.api_payload())) as request, \
             contextlib.redirect_stdout(io.StringIO()):
            enrichment.run_enrichment(self.db, self.network, targets)

        http_request = request.call_args.args[0]
        self.assertEqual(f'http://{ip}:8001/api/v2/', http_request.full_url)
        self.assertEqual('GET', http_request.get_method())
        self.assertEqual(3, request.call_args.kwargs['timeout'])

        inventory = database.get_inventory(self.db, device_id, network_id=self.network)[0]
        identification = inventory['device_identification']
        self.assertEqual('confirmed', identification['status'])
        self.assertEqual('GU75AU7179UXZG', identification['model'])
        self.assertEqual('Samsung AU7179 75 TV', identification['name'])
        self.assertEqual('Tizen', identification['operating_system'])
        self.assertEqual('Wohnzimmer-TV', self.db.execute(
            'SELECT display_name FROM devices WHERE id=?', (device_id,)).fetchone()[0])

        result = classify_and_store_inventory(self.db, self.network)
        self.assertEqual(1, result['evaluated'])
        classification = self.db.execute(
            'SELECT * FROM device_classifications WHERE network_id=? AND device_id=?',
            (self.network, device_id)).fetchone()
        self.assertEqual('smart_tv', classification['category'])
        self.assertEqual('Samsung Smart-TV', classification['subtype'])
        self.assertGreaterEqual(classification['confidence'], 85)
        self.assertEqual('samsung_smart_tv_api', classification['source'])

        with tempfile.TemporaryDirectory() as directory:
            snapshot = sqlite3.connect(f'{directory}/inventory.db')
            self.db.backup(snapshot)
            snapshot.close()
            reopened = sqlite3.connect(f'{directory}/inventory.db')
            reopened.row_factory = sqlite3.Row
            restored = database.get_inventory(reopened, device_id, network_id=self.network)[0]
            self.assertEqual('GU75AU7179UXZG', restored['device_identification']['model'])
            self.assertEqual([], enrichment.device_enrichment_due(
                reopened, self.network, restored))
            self.assertEqual('smart_tv', reopened.execute(
                'SELECT category FROM device_classifications WHERE network_id=? AND device_id=?',
                (self.network, device_id)).fetchone()['category'])
            reopened.close()

        self.assertEqual([], enrichment.device_enrichment_due(
            self.db, self.network, inventory))
        selected_again, stats_again = enrichment.get_enrichment_targets(self.db, self.network)
        self.assertEqual(0, stats_again['device_targets'])
        self.assertFalse(any(device.get('_device_enrichers') for device, _ in selected_again))

    def test_successful_probe_is_not_repeated_before_seven_days(self):
        device_id, _ = self.samsung()
        device = database.get_inventory(self.db, device_id, network_id=self.network)[0]
        run_id = database.start_scan_run(self.db, self.network, 'enrichment')
        result = {'status':'confirmed','source':'samsung_smart_tv_api',
                  'manufacturer':'Samsung','type':'Samsung Smart-TV','model':'GU75AU7179UXZG'}
        with atomic(self.db):
            self.db.execute("""INSERT INTO observations(network_id,device_id,scan_run_id,
                observation_type,source,data_json) VALUES(?,?,?,'device_enrichment_attempt',?,?)""",
                (self.network, device_id, run_id, 'samsung_smart_tv_api', json.dumps(result)))
        self.assertEqual([], enrichment.device_enrichment_due(self.db, self.network, device))
        self.db.execute("""UPDATE observations SET observed_at=datetime('now','-8 days')
            WHERE device_id=? AND observation_type='device_enrichment_attempt'""", (device_id,))
        self.db.commit()
        self.assertEqual(['samsung_smart_tv_api'],
                         enrichment.device_enrichment_due(self.db, self.network, device))

    def test_bad_responses_do_not_create_false_identification(self):
        device_id, _ = self.samsung()
        device = database.get_inventory(self.db, device_id, network_id=self.network)[0]
        cases = [
            (TimeoutError('timeout'), 'connection_error'),
            (io.BytesIO(b'{invalid json'), 'invalid_json'),
            (io.BytesIO(self.api_payload('Android TV')), 'not_samsung_smart_tv'),
        ]
        for response, reason in cases:
            patch_options = ({'side_effect': response} if isinstance(response, Exception)
                             else {'return_value': response})
            with self.subTest(reason=reason), patch('device_enrichment.urlopen', **patch_options):
                result = device_enrichment.get_enricher('samsung_smart_tv_api').probe(device)
                self.assertEqual('error', result['status'])
                self.assertEqual(reason, result['reason'])
        self.assertIsNone(database.get_inventory(self.db, device_id, network_id=self.network)[0]
                          ['device_identification'])
        suspected = classify_device(device)
        self.assertLess(suspected['confidence'], 85)
        self.assertNotEqual('samsung_smart_tv_api', suspected.get('source'))

    def test_samsung_request_disables_redirects_and_proxies(self):
        from urllib.request import ProxyHandler, Request
        handler = device_enrichment._NoRedirect()
        self.assertIsNone(handler.redirect_request(
            Request('http://192.0.2.8:8001/api/v2/'), None, 302, 'Found', {},
            'http://example.com/'))
        response = io.BytesIO(self.api_payload('Samsung SmartTV'))
        with patch('device_enrichment.build_opener') as build:
            build.return_value.open.return_value = response
            request = Request('http://192.0.2.8:8001/api/v2/')
            self.assertIs(response, device_enrichment.urlopen(request, 3))
            self.assertTrue(any(isinstance(item, ProxyHandler) and not item.proxies
                                for item in build.call_args.args))
            self.assertTrue(any(isinstance(item, device_enrichment._NoRedirect)
                                for item in build.call_args.args))

    def test_connection_error_is_persisted_and_retried_after_cooldown(self):
        device_id, _ = self.samsung()
        device = database.get_inventory(self.db, device_id, network_id=self.network)[0]
        run_id = database.start_scan_run(self.db, self.network, 'enrichment')
        with patch('device_enrichment.urlopen', side_effect=TimeoutError('simulated')):
            result = enrichment.run_device_enricher(
                self.db, self.network, run_id, device, 'samsung_smart_tv_api')
        self.assertEqual('connection_error', result['reason'])
        self.assertIsNone(database.get_inventory(self.db, device_id, network_id=self.network)[0]
                          ['device_identification'])
        self.assertEqual([], enrichment.device_enrichment_due(self.db, self.network, device))
        self.db.execute("""UPDATE observations SET observed_at=datetime('now','-2 hours')
            WHERE device_id=? AND observation_type='device_enrichment_attempt'""", (device_id,))
        self.db.commit()
        self.assertEqual(['samsung_smart_tv_api'],
                         enrichment.device_enrichment_due(self.db, self.network, device))

    def test_weaker_or_contradictory_detection_cannot_replace_saved_classification(self):
        device_id, _ = self.samsung()
        saved = {'category':'camera','subtype':'Kamera','confidence':95,
                 'score':100,'evidence':[],'source':'classifier'}
        self.assertTrue(save_classification(self.db, self.network, device_id, saved))
        result = {'category':'smart_tv','subtype':'Samsung Smart-TV','confidence':94,
                  'score':100,'evidence':[],'source':'samsung_smart_tv_api'}
        self.assertFalse(save_classification(self.db, self.network, device_id, result))
        current = self.db.execute('SELECT category,source FROM device_classifications WHERE device_id=?',
                                  (device_id,)).fetchone()
        self.assertEqual(('camera','classifier'), tuple(current))
        result['confidence'] = 95
        self.assertFalse(save_classification(self.db, self.network, device_id, result))
        self.assertEqual('camera', self.db.execute(
            'SELECT category FROM device_classifications WHERE device_id=?',
            (device_id,)).fetchone()['category'])

    def test_manual_classification_is_not_replaced_by_automatic_detection(self):
        device_id, _ = self.samsung()
        saved = {'category':'camera','subtype':'Manuell festgelegt','confidence':80,
                 'score':50,'evidence':[],'source':'manual'}
        self.assertTrue(save_classification(self.db, self.network, device_id, saved))
        result = {'category':'smart_tv','subtype':'Samsung Smart-TV','confidence':99,
                  'score':200,'evidence':[],'source':'samsung_smart_tv_api'}
        self.assertFalse(save_classification(self.db, self.network, device_id, result))
        current = self.db.execute('SELECT category,source FROM device_classifications WHERE device_id=?',
                                  (device_id,)).fetchone()
        self.assertEqual(('camera','manual'), tuple(current))


if __name__ == '__main__':
    unittest.main()
