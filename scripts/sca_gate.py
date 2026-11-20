#!/usr/bin/env python3
import argparse,json
from collections import Counter
from pathlib import Path
ap=argparse.ArgumentParser();ap.add_argument('report');ap.add_argument('--summary',required=True);a=ap.parse_args()
p=Path(a.report)
try:d=json.loads(p.read_text())
except Exception as e:
 print(f'FAIL CLOSED: отчёт SCA недоступен или повреждён: {e}');raise SystemExit(1)
vulns=[]
for result in d.get('Results',[]):
 for v in result.get('Vulnerabilities') or []:
  cvss=v.get('CVSS',{}).get('nvd',{}).get('V3Score',0.0)
  vulns.append({'id':v['VulnerabilityID'],'package':v['PkgName'],'version':v.get('InstalledVersion',''),'severity':v.get('Severity','UNKNOWN'),'cvss':cvss,'fixed':v.get('FixedVersion','')})
counts=Counter(v['severity'] for v in vulns)
blocking=[v for v in vulns if v['severity'] in {'CRITICAL','HIGH'} or v['cvss']>6.9]
summary={'status':'blocked' if blocking else 'passed','scanner':d.get('SchemaVersion'),'total':len(vulns),'severity':dict(counts),'blocking_count':len(blocking),'blocking_reasons':[f"{v['id']} {v['package']} {v['version']} CVSS {v['cvss']}" for v in blocking]}
Path(a.summary).write_text(json.dumps(summary,ensure_ascii=False,indent=2))
print('=== Security Gate: политика SCA ===')
print(f"Найдено: CRITICAL={counts['CRITICAL']}, HIGH={counts['HIGH']}, MEDIUM={counts['MEDIUM']}, LOW={counts['LOW']}")
for v in blocking:print(f"BLOCK {v['id']} | {v['package']} {v['version']} | {v['severity']} {v['cvss']} | fix: {v['fixed']}")
print('РЕЗУЛЬТАТ:',summary['status'].upper())
raise SystemExit(1 if blocking else 0)
