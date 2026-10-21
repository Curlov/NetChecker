import unittest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from classifier import classify_device
from fingerprints import load_rules, match_device
import fingerprints


class AppleMobileClassificationTest(unittest.TestCase):
    def device(self, **overrides):
        device = {
            "ip": "192.168.10.184",
            "mac": "00:11:22:33:44:55",
            "vendor": None,
            "hostname": "",
            "ports": [{"protocol": "tcp", "port": 62078, "state": "open"}],
        }
        device.update(overrides)
        return device

    def test_open_iphone_sync_port_classifies_unknown_device_with_medium_confidence(self):
        result = classify_device(self.device())

        self.assertEqual("apple_device", result["category"])
        self.assertEqual("Mögliches iPhone / iPad", result["subtype"])
        self.assertEqual(60, result["score"])
        self.assertEqual(73, result["confidence"])
        self.assertIn(
            "TCP-Port 62078 ist offen; Apple-Mobilgerät möglich",
            [item["reason"] for item in result["evidence"]],
        )

    def test_recognized_iphone_sync_service_raises_confidence(self):
        result = classify_device(self.device(ports=[{
            "protocol": "tcp", "port": 62078, "state": "open", "service": "iphone-sync"
        }]))

        self.assertEqual("apple_device", result["category"])
        self.assertEqual(85, result["score"])
        self.assertGreater(result["confidence"], 70)
        self.assertIn(
            "TCP-Port 62078 meldet den Apple-Dienst iphone-sync",
            [item["reason"] for item in result["evidence"]],
        )

    def test_apple_mac_vendor_is_used_as_corroborating_evidence(self):
        result = classify_device(self.device(vendor="Apple, Inc."))

        self.assertEqual("apple_device", result["category"])
        self.assertEqual(70, result["score"])
        self.assertIn(
            "MAC-Hersteller weist zusätzlich auf Apple hin",
            [item["reason"] for item in result["evidence"]],
        )

    def test_closed_or_udp_62078_does_not_trigger_apple_classification(self):
        for port in (
            {"protocol": "tcp", "port": 62078, "state": "closed"},
            {"protocol": "udp", "port": 62078, "state": "open"},
        ):
            with self.subTest(port=port):
                result = classify_device(self.device(ports=[port]))
                self.assertEqual("unknown", result["category"])

    def test_62078_does_not_displace_a_classifiable_conflicting_hint(self):
        result = classify_device(self.device(ports=[
            {"protocol": "tcp", "port": 62078, "state": "open"},
            {"protocol": "tcp", "port": 9100, "state": "open"},
        ]))

        self.assertEqual("printer", result["category"])
        self.assertEqual(60, result["score"])


class ExistingNmapEvidenceTest(unittest.TestCase):
    def device(self, **overrides):
        value = {"ip": "192.0.2.8", "mac": "00:11:22:33:44:55",
                 "vendor": None, "hostname": None, "ports": []}
        value.update(overrides)
        return value

    def test_probed_pve_api_daemon_is_strong_evidence(self):
        result = classify_device(self.device(ports=[{
            "protocol": "tcp", "port": 8006, "state": "open",
            "service": "https", "product": "pve-api-daemon", "method": "probed",
        }]))
        self.assertEqual("virtualization", result["category"])
        self.assertGreaterEqual(result["confidence"], 90)
        self.assertTrue(any("pve-api-daemon" in item["reason"] for item in result["evidence"]))

    def test_port_only_is_not_confirmed_product(self):
        result = classify_device(self.device(ports=[{
            "protocol": "tcp", "port": 8006, "state": "open",
            "service": "http", "method": "table",
        }]))
        self.assertLess(result["confidence"], 85)
        self.assertFalse(any("bestätigt" in item["reason"] for item in result["evidence"]))

    def test_nmap_wap_osclass_is_used(self):
        result = classify_device(self.device(os_classes=[{"type": "WAP", "vendor": "Unknown"}]))
        self.assertEqual("network_device", result["category"])
        self.assertTrue(any("WAP" in item["reason"] for item in result["evidence"]))

    def test_local_fingerprint_rule_has_revision_and_evidence(self):
        rules = load_rules()
        self.assertTrue(any(rule['id'] == 'hpe-ilo' for rule in rules))
        device = self.device(ports=[{"protocol": "tcp", "port": 443,
                                    "state": "open", "product": "HP Integrated Lights-Out 5"}])
        findings = match_device(device)
        self.assertEqual('hpe-ilo', findings[0]['rule_id'])
        self.assertIn('@2026-10-21.1', findings[0]['reason'])
        result = classify_device(device)
        self.assertEqual('network_device', result['category'])
        self.assertEqual('HPE iLO', result['subtype'])

    def test_port_name_alone_does_not_match_local_fingerprint(self):
        device = self.device(ports=[{"protocol": "tcp", "port": 443,
                                    "state": "open", "service": "hpe-ilo", "method": "table"}])
        self.assertEqual([], match_device(device))

    def test_small_external_local_rule_file_can_be_matched(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'local-rules.json'
            path.write_text(json.dumps({
                'schema': 1, 'revision': 'test.1', 'source': 'curated external test',
                'rules': [{'id': 'distinct-test-product', 'category': 'network_device',
                           'points': 70, 'subtype': 'Testgerät',
                           'any': [{'field': 'product', 'contains': 'Unique Test Appliance'}]}],
            }), encoding='utf-8')
            try:
                with patch.object(fingerprints, 'LOCAL_RULES_PATH', path):
                    load_rules.cache_clear()
                    findings = match_device(self.device(ports=[{
                        'protocol':'tcp', 'port':443, 'state':'open',
                        'product':'Unique Test Appliance',
                    }]))
                self.assertTrue(any(item['rule_id'] == 'distinct-test-product' and
                                    item['rule_source'] == 'curated external test'
                                    for item in findings))
            finally:
                load_rules.cache_clear()

    def test_conflicting_product_fingerprint_reduces_confidence(self):
        plain = classify_device(self.device(ports=[{
            "protocol": "tcp", "port": 443, "state": "open", "product": "HP Integrated Lights-Out 5"
        }]))
        conflict = classify_device(self.device(ports=[
            {"protocol": "tcp", "port": 443, "state": "open", "product": "HP Integrated Lights-Out 5"},
            {"protocol": "tcp", "port": 80, "state": "open", "product": "Reolink IPC"},
        ]))
        self.assertLess(conflict['confidence'], plain['confidence'])

    def test_vendor_only_stays_below_high_confidence(self):
        for vendor in ('Yealink', 'Reolink', 'Ubiquiti', 'MikroTik', 'Sophos'):
            with self.subTest(vendor=vendor):
                result = classify_device(self.device(vendor=vendor))
                self.assertLess(result['confidence'], 85)

    def test_supported_products_use_saved_service_evidence(self):
        cases = (
            ('proxmox-backup-proxy', 'virtualization', 'Proxmox Backup Server'),
            ('Aruba Instant On', 'network_device', 'HPE Aruba Instant On'),
            ('Ubiquiti UniFi', 'network_device', 'Ubiquiti UniFi'),
            ('Yealink SIP', 'voip_phone', 'Yealink VoIP-Telefon'),
            ('Reolink IPC', 'camera', 'Reolink IP-Kamera'),
            ('Internet Printing Protocol', 'printer', 'Netzwerkdrucker'),
        )
        for product, category, subtype in cases:
            with self.subTest(product=product):
                result = classify_device(self.device(ports=[{
                    'protocol': 'tcp', 'port': 443, 'state': 'open', 'product': product,
                    'method': 'probed',
                }]))
                self.assertEqual(category, result['category'])
                self.assertEqual(subtype, result['subtype'])

    def test_samsung_clues_remain_suspected_without_api(self):
        result = classify_device(self.device(vendor='Samsung Electronics', ports=[
            {'protocol':'tcp','port':8001,'state':'open'},
            {'protocol':'tcp','port':8002,'state':'open'},
        ]))
        self.assertEqual('smart_tv', result['category'])
        self.assertEqual('Möglicher Samsung Smart-TV', result['subtype'])
        self.assertNotEqual('samsung_smart_tv_api', result.get('source'))
        self.assertLess(result['confidence'], 85)


class PersistedNmapEvidenceTest(unittest.TestCase):
    from tests.test_offline import InventoryTest as _Inventory
    setUp = _Inventory.setUp
    tearDown = _Inventory.tearDown
    host = _Inventory.host

    def test_saved_osclass_and_http_script_reach_classifier(self):
        import database
        import enrichment
        device_id, run_id = self.host()
        enrichment.persist_enrichment_result(self.db, self.network, run_id,
            {'id': device_id, 'ip': '192.0.2.10'}, {
                'status': 'success',
                'ports': [{'protocol': 'tcp', 'port': 443, 'state': 'open',
                           'service': 'https', 'scripts': [
                               {'id': 'http-title', 'output': 'Aruba Instant On'}]}],
                'os_classes': [{'type': 'WAP', 'vendor': 'HPE'}],
                'scan_metadata': {'complete': True, 'scaninfo': [
                    {'protocol': 'tcp', 'services': '443'}]},
            }, 'light')
        restored = database.get_inventory(self.db, device_id, network_id=self.network)[0]
        self.assertEqual('WAP', restored['os_classes'][0]['type'])
        self.assertEqual('Aruba Instant On', restored['ports'][0]['scripts'][0]['output'])
        classification = classify_device(restored)
        self.assertEqual('network_device', classification['category'])
        self.assertEqual('HPE Aruba Instant On', classification['subtype'])
        import sqlite3
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'inventory.db'
            copy = sqlite3.connect(path)
            self.db.backup(copy)
            copy.close()
            reopened = sqlite3.connect(path)
            reopened.row_factory = sqlite3.Row
            persisted = database.get_inventory(reopened, device_id, network_id=self.network)[0]
            self.assertEqual('HPE Aruba Instant On', classify_device(persisted)['subtype'])
            reopened.close()


if __name__ == "__main__":
    unittest.main()
