#!/usr/bin/env python3
import json,re,sys,uuid
from pathlib import Path
ok=True
for arg in sys.argv[1:]:
 p=Path(arg)
 try:
  d=json.loads(p.read_text())
  assert d['bomFormat']=='CycloneDX' and d['specVersion']=='1.6'
  assert str(uuid.UUID(d['serialNumber'].removeprefix('urn:uuid:')))
  assert d['metadata']['component']['name']
  assert isinstance(d['components'],list) and d['components']
  for c in d['components']:
   assert c['name'] and c['version'] and c['bom-ref']
   assert c['purl'].startswith('pkg:') and '@' in c['purl']
   assert c.get('licenses'), f"нет лицензии: {c['name']}"
  print(f"OK {p.name}: CycloneDX {d['specVersion']}, компонентов {len(d['components'])}, PURL и лицензии заполнены")
 except Exception as e:
  ok=False;print(f"FAIL {p.name}: {e}")
raise SystemExit(0 if ok else 1)
