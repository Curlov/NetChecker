"""Verify vendored SVG assets offline; no downloading during tests."""
import hashlib
import json
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


class LucideAssetsTest(unittest.TestCase):
    def test_local_sprite_matches_manifest_and_license(self):
        directory = Path('web/static/vendor/lucide')
        manifest = json.loads((directory/'manifest.json').read_text())
        self.assertEqual('Lucide',manifest['project'])
        for filename,digest in manifest['sha256'].items():
            self.assertEqual(digest,hashlib.sha256((directory/filename).read_bytes()).hexdigest())
        sprite = ET.parse(directory/'sprite.svg').getroot()
        self.assertEqual(set(manifest['icons']),{symbol.attrib['id'] for symbol in sprite})
        self.assertIn('ISC License',(directory/'LICENSE').read_text())
        self.assertIn('MIT',(directory/'FEATHER-LICENSE').read_text())
        for symbol in sprite:
            self.assertEqual('0 0 24 24',symbol.attrib['viewBox'])
            for element in symbol.iter():
                self.assertNotIn(element.tag.split('}')[-1],{'script','foreignObject','image'})
