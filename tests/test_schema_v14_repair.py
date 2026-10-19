import sqlite3
import tempfile
import unittest
from pathlib import Path

import database
import schema
from startup_migrations import migrate_connection_for_startup


class SchemaV14RepairTest(unittest.TestCase):
    def test_current_version_missing_ever_open_is_backed_up_and_repaired(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'netchecker.db'
            connection = sqlite3.connect(path)
            connection.row_factory = sqlite3.Row
            connection.execute('PRAGMA foreign_keys=ON')
            schema.initialize_database(connection)
            network = database.save_network(connection, '192.0.2.0/24', 'test0', None)
            run = database.start_scan_run(connection, network, 'detail')
            device = database.save_discovery_host(connection, network, run, {
                'ip': '192.0.2.10', 'mac': '00:11:22:33:44:55'})
            database.save_port_scan(connection, network, run, {
                'device_id': device, 'ip': '192.0.2.10',
                'ports': [{'protocol': 'tcp', 'port': 22, 'state': 'open'}],
                'scan_metadata': {'complete': True, 'scaninfo': [{'protocol': 'tcp', 'services': '22'}]},
            }, source='test', observation_type='tcp_port_scan')
            database.finish_scan_run(connection, run)
            before = {table: connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
                      for table in ('devices', 'port_inventory', 'observations', 'changes')}
            connection.execute('ALTER TABLE port_inventory DROP COLUMN ever_open')
            connection.commit()

            result = migrate_connection_for_startup(connection, path, component='scanner')

            self.assertEqual(schema.SCHEMA_VERSION, connection.execute('PRAGMA user_version').fetchone()[0])
            self.assertIn('ever_open', {row['name'] for row in connection.execute('PRAGMA table_info(port_inventory)')})
            self.assertEqual(1, connection.execute(
                'SELECT ever_open FROM port_inventory WHERE network_id=? AND device_id=? AND port=22',
                (network, device)).fetchone()[0])
            self.assertEqual(before, {table: connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
                                      for table in before})
            self.assertEqual([22], database.get_historically_open_tcp_ports(connection, network, device))
            self.assertIsNotNone(result['backup_path'])
            backup = sqlite3.connect(result['backup_path'])
            try:
                self.assertEqual('ok', backup.execute('PRAGMA integrity_check').fetchone()[0])
                self.assertEqual(schema.SCHEMA_VERSION, backup.execute('PRAGMA user_version').fetchone()[0])
                self.assertNotIn('ever_open', {row[1] for row in backup.execute('PRAGMA table_info(port_inventory)')})
            finally:
                backup.close()
                Path(result['backup_path']).unlink()
            connection.close()


if __name__ == '__main__':
    unittest.main()
