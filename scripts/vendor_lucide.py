"""Vendor a pinned Lucide SVG subset. Explicit developer tool, never runtime code."""
from pathlib import Path
from urllib.request import urlopen, Request
import copy
import hashlib
import json
import xml.etree.ElementTree as ET

VERSION = '1.55.0'
ICONS = ('circle-plus','circle-minus','circle-check','circle-x','info',
         'triangle-alert','arrow-right-left','refresh-cw','chevron-down',
         'router','network','boxes','server','monitor','monitor-smartphone','phone',
         'printer','camera','battery-charging','cpu','circle-question-mark')
BASE = f'https://raw.githubusercontent.com/lucide-icons/lucide/{VERSION}'
TARGET = Path(__file__).resolve().parents[1] / 'web/static/vendor/lucide'
NS = 'http://www.w3.org/2000/svg'


def download(url):
    with urlopen(Request(url, headers={'User-Agent':'NetChecker-icon-vendoring'}), timeout=20) as response:
        payload = response.read(256_001)
    if len(payload) > 256_000:
        raise ValueError('Unexpectedly large upstream asset')
    return payload


def main():
    assets = {'LICENSE':download(BASE+'/LICENSE'),
              'FEATHER-LICENSE':download('https://raw.githubusercontent.com/feathericons/feather/v4.29.2/LICENSE')}
    ET.register_namespace('',NS)
    sprite = ET.Element(f'{{{NS}}}svg')
    allowed_tags = {'svg','path','circle','rect','line','polyline','polygon','ellipse','g'}
    for name in ICONS:
        payload = download(BASE+'/icons/'+name+'.svg')
        root = ET.fromstring(payload)
        for element in root.iter():
            if element.tag.split('}')[-1] not in allowed_tags:
                raise ValueError('Unexpected SVG element')
            if any(key.lower().startswith('on') or key.endswith('href') or key=='style' for key in element.attrib):
                raise ValueError('Unexpected active SVG attribute')
        symbol = ET.SubElement(sprite,f'{{{NS}}}symbol',id=name,viewBox=root.get('viewBox','0 0 24 24'))
        for child in root:
            symbol.append(copy.deepcopy(child))
        assets[name+'.svg'] = payload
    assets['sprite.svg'] = ET.tostring(sprite,encoding='utf-8',xml_declaration=True)
    assets['manifest.json'] = (json.dumps({'project':'Lucide','version':VERSION,'source':BASE,
        'icons':list(ICONS),'sha256':{name:hashlib.sha256(payload).hexdigest() for name,payload in assets.items()}},indent=2)+'\n').encode()
    assets['README.md'] = (f'# Lucide {VERSION}\n\nLocal SVG subset from https://github.com/lucide-icons/lucide/releases/tag/{VERSION}.\n'
        'Original SVGs and licenses are included; sprite.svg is generated without changing icon geometry.\n'
        'Update explicitly with python3 -B scripts/vendor_lucide.py. No runtime downloads or CDN.\n').encode()
    TARGET.mkdir(parents=True,exist_ok=True)
    for name,payload in assets.items():
        (TARGET/name).write_bytes(payload)
    print(f'Lucide {VERSION}: {len(ICONS)} local SVG icons and licenses vendored')


if __name__ == '__main__':
    main()
