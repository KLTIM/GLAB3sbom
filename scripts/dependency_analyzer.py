#!/usr/bin/env python3
import json,re
from pathlib import Path
root=Path(__file__).resolve().parents[1]
data=json.loads((root/'security/dependency_inventory.json').read_text())
patterns={'openssl':re.compile(r'openssl/(hmac|sha|evp)\.h'), 'mbedtls':re.compile(r'mbedtls/(ecdsa|sha256|pk)\.h'), 'cjson':re.compile(r'cjson/cJSON\.h'), 'curl':re.compile(r'curl/curl\.h')}
rows=[]
for v in data['variants']:
 text=(root/v['file']).read_text()
 found=[k for k,p in patterns.items() if p.search(text)]
 rows.append({'variant':v['id'],'student':v['student'],'file':v['file'],'includes':found,'declared':v['components'],'match':set(found)==set(v['components'])})
print('=== Инвентаризация зависимостей: вариант 24 ===')
for r in rows:
 print(f"{r['student']}: {', '.join(r['includes'])} | соответствие SBOM: {'OK' if r['match'] else 'ОШИБКА'}")
print(f"Проверено прошивок: {len(rows)}; уникальных библиотек: {len(data['components'])}")
if not all(r['match'] for r in rows): raise SystemExit(1)
(root/'reports').mkdir(exist_ok=True)
(root/'reports/dependency-analysis.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2))
