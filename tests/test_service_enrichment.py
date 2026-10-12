"""Independent service selection, scan budget and persistence with no network."""
import contextlib
import io
import json
import os
import unittest
from unittest.mock import patch

import database
import enrichment
from transactions import atomic
from tests import test_offline as fixtures


class ServiceEnrichmentTest(unittest.TestCase):
    setUp = fixtures.InventoryTest.setUp
    tearDown = fixtures.InventoryTest.tearDown
    host = fixtures.InventoryTest.host
    ports = fixtures.InventoryTest.ports

    def prepared(self, number=10, os_known=True):
        device,run = self.host(ip=f'192.0.2.{number}',mac=f'00:11:22:33:44:{number:02X}')
        with atomic(self.db):
            database.set_device_present(self.db,self.network,device,run)
        self.ports(device,[{'protocol':'tcp','port':22,'state':'open','service':'ssh'}])
        if os_known:
            database.save_os_information(self.db,self.network,run,{'device_id':device,'ip':f'192.0.2.{number}',
                'os':{'name':'Linux 6.x','accuracy':95,'source':'nmap_os'}})
        return device

    def select(self):
        with patch.dict(os.environ,{'NETCHECKER_SERVICE_MAX_HOSTS':'4','NETCHECKER_SERVICE_RETRY_DAYS':'7'}):
            return enrichment.get_enrichment_targets(self.db,self.network)

    def service_result(self, ports=(22,)):
        return {'status':'success','os':None,
            'ports':[{'protocol':'tcp','port':port,'state':'open','service':'ssh',
                'product':'OpenSSH','version':'9.9','method':'probed'} for port in ports],
            'scan_metadata':{'complete':True,'scaninfo':[{'protocol':'tcp','services':','.join(map(str,ports))}]}}

    def test_known_os_still_selects_services(self):
        device = self.prepared()
        targets,stats = self.select()
        self.assertEqual(1,stats['os_known'])
        self.assertEqual(1,stats['service_targets'])
        self.assertEqual(device,targets[0][0]['id'])
        self.assertEqual('service',targets[0][0]['_enrichment_goal'])

    def test_high_classification_still_selects_services(self):
        self.prepared(os_known=False)
        self.db.execute("UPDATE devices SET vendor='Yealink'"); self.db.commit()
        targets,stats = self.select()
        self.assertEqual(1,stats['classified'])
        self.assertEqual('service',targets[0][0]['_enrichment_goal'])

    def test_budget_and_zero_budget(self):
        for number in range(10,16): self.prepared(number)
        targets,stats = self.select()
        self.assertEqual(4,len(targets))
        self.assertEqual(2,stats['service_deferred'])
        with patch.dict(os.environ,{'NETCHECKER_SERVICE_MAX_HOSTS':'0'}):
            self.assertEqual([],enrichment.get_enrichment_targets(self.db,self.network)[0])

    def test_success_updates_versions_without_os_or_deep_scan(self):
        device = self.prepared()
        enrichment.save_enrichment_status(self.db,self.network,device,'no_os_detected',True,True)
        targets,_ = self.select()
        with patch('enrichment.scan_services',return_value=self.service_result()), \
             patch('enrichment.enrich_device',side_effect=AssertionError('OS scan')), \
             patch('enrichment.scan_deep',side_effect=AssertionError('DEEP scan')), \
             patch('subprocess.run',side_effect=AssertionError('Real external command')), \
             contextlib.redirect_stdout(io.StringIO()):
            enrichment.run_enrichment(self.db,self.network,targets)
        port = database.get_port_inventory(self.db,self.network,device)[0]
        self.assertEqual('OpenSSH',port['product']); self.assertEqual('9.9',port['version'])
        self.assertEqual('no_os_detected',enrichment.get_enrichment_status(self.db,self.network,device)['status'])
        self.assertEqual('Linux 6.x',database.get_inventory(self.db,device,network_id=self.network)[0]['os']['name'])
        self.assertEqual([],self.select()[0])

    def test_new_port_is_selected_without_reprobing_recent_ports(self):
        device = self.prepared()
        selected = self.select()[0][0][0]
        run = database.start_scan_run(self.db,self.network,'enrichment')
        with patch('enrichment.scan_services',return_value=self.service_result()):
            enrichment.enrich_services(self.db,self.network,run,selected)
        self.ports(device,[{'protocol':'tcp','port':22,'state':'open'},
                           {'protocol':'tcp','port':80,'state':'open'}],covered='22,80')
        selected = self.select()[0][0][0]
        self.assertEqual([80],enrichment.build_service_ports(selected))
        with patch('enrichment.scan_services',return_value=self.service_result((80,))):
            enrichment.enrich_services(self.db,self.network,run,selected)
        self.assertEqual([],self.select()[0])

    def test_failed_attempt_has_cooldown(self):
        device = self.prepared()
        selected = self.select()[0][0][0]
        run = database.start_scan_run(self.db,self.network,'enrichment')
        with patch('enrichment.scan_services',return_value={'status':'timeout','ports':[],'os':None}):
            self.assertTrue(enrichment.enrich_services(self.db,self.network,run,selected)['timeout'])
        self.assertEqual([],self.select()[0])
        self.db.execute("UPDATE observations SET observed_at=datetime('now','-2 hours') WHERE observation_type='service_enrichment_attempt'")
        self.db.commit()
        self.assertEqual(1,len(self.select()[0]))

    def test_services_use_only_known_open_tcp_without_os_scripts(self):
        device = {'ip':'192.0.2.2','ports':[{'protocol':'tcp','port':22,'state':'open'},
            {'protocol':'tcp','port':80,'state':'closed'},{'protocol':'udp','port':53,'state':'open'}]}
        with patch('enrichment.execute_nmap',return_value=self.service_result()) as execute:
            enrichment.scan_services(device)
        command = execute.call_args.args[0]
        self.assertEqual('22',command[command.index('-p')+1])
        self.assertIn('-sV',command); self.assertIn('--version-light',command)
        for option in ('-O','--script','--version-all','--top-ports'):
            self.assertNotIn(option,command)

    def test_os_candidate_is_not_added_twice(self):
        self.prepared(os_known=False)
        targets,stats = self.select()
        self.assertEqual(1,len(targets)); self.assertEqual(0,stats['service_targets'])
        self.assertNotEqual('service',targets[0][0].get('_enrichment_goal'))
