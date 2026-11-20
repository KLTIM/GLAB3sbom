#!/usr/bin/env python3
import argparse,json,uuid
from pathlib import Path
ap=argparse.ArgumentParser();ap.add_argument('--fixed',action='store_true');ap.add_argument('--output',required=True);a=ap.parse_args()
root=Path(__file__).resolve().parents[1]
data=json.loads((root/'security/dependency_inventory.json').read_text())
components=[]
for c in data['components'].values():
 ver=c['fixed'] if a.fixed else c['version'];purl=c['fixed_purl'] if a.fixed else c['purl']
 components.append({'type':'library','bom-ref':purl,'name':c['name'],'version':ver,'purl':purl,'cpe':c['cpe'].replace(c['version'],ver),'description':c['description'],'licenses':[{'license':{'id':c['license']}}]})
root_ref='taxi-firmware'
d={'bomFormat':'CycloneDX','specVersion':'1.6','serialNumber':'urn:uuid:'+str(uuid.uuid4()),'version':1,'metadata':{'component':{'type':'firmware','bom-ref':root_ref,'name':'Autonomous Taxi Embedded Security Suite','version':'1.0.0'}},'components':components,'dependencies':[{'ref':root_ref,'dependsOn':[c['bom-ref'] for c in components]}]}
out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(d,ensure_ascii=False,indent=2))
print(f'{out}: {len(components)} компонентов, CycloneDX 1.6')
