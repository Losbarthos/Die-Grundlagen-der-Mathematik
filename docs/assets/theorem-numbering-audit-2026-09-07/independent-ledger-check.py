from pathlib import Path
import json, re, runpy, hashlib

P=runpy.run_path('scripts/proof-source-audit.py')
base=Path('docs/assets/theorem-numbering-audit-2026-09-07')
names=['b01-b14-b19-changes.json','b15-b27-changes.json','b28-changes.json']
records=[]
for name in names:
    records += [(name,r) for r in json.loads((base/name).read_text(encoding='utf-8'))]
assert len(records)==58,len(records)
ids=[r.get('id',r.get('key')) for _,r in records]
assert len(set(ids))==58
sources={}
calls={}
for _,r in records:
    name=r['file']
    if name in sources:continue
    source=Path(name).read_text(encoding='utf-8')
    sources[name]=source
    masked=P['mask_comments'](source)
    for m in re.finditer(r'\\FormulaThmDeltaKR\b',masked):
        c=P['call'](masked,m.start(),4)
        args=[source[slice(*x)] for x in c.args]
        ident=args[2]
        assert (name,ident) not in calls,(name,ident)
        calls[(name,ident)]={'display':args[0],'structure':args[1],
                             'line':source.count('\n',0,m.start())+1}

registry_ids={}
registry_numbers={}
for band in range(1,45):
    path=Path(f'registry/_B{band:02d}.registry.tsv')
    for line in path.read_text(encoding='utf-8').splitlines():
        f=line.split('\t')
        if f[0]=='ID' and len(f)>=4:registry_ids[(band,f[1])]=f[3]
        elif f[0]=='1' and len(f)>=4:registry_numbers[(band,f[1])]=f[3]

issues=[]
checked=[]
total_tags=0
roman=['i','ii','iii','iv','v','vi','vii','viii','ix','x','xi','xii']
for ledger,r in records:
    ident=r.get('id',r.get('key'))
    c=calls.get((r['file'],ident))
    if not c:
        issues.append({'id':ident,'issue':'KR call missing'});continue
    tags=re.findall(r'\\text\{\(([ivxlcdm]+)\)\}',c['display'])
    total_tags+=len(tags)
    band=int(re.search(r'(?:Bd\. |B)(\d{2})',r['file'])[1])
    label=registry_ids.get((band,ident))
    number=registry_numbers.get((band,label))
    checks={
      'original_structure_exact':c['structure']==r['original_structural_key'],
      'current_display_exact':c['display']==r['current_display'],
      'visible_tags_exact':tags==r['current_visible_tags'],
      'visible_tags_sequential':tags==roman[:len(tags)],
      'theorem_number_exact':number==r['current_theorem_number'],
      'source_line_exact':c['line']==r['current_source_line'],
      'source_sha256_exact':hashlib.sha256(Path(r['file']).read_bytes()).hexdigest()==r['current_source_sha256']
    }
    for check,passed in checks.items():
        if not passed:issues.append({'id':ident,'issue':check,'source_line':c['line'],
                                    'registry_number':number,'visible_tags':tags})
    checked.append({'id':ident,'file':r['file'],'ledger':ledger,'current_theorem_number':number,
                    'visible_tags':tags,'checks':checks})
result={'reviewer':'audit_b15_b27','families':len(checked),'visible_tags':total_tags,
        'all_58_original_structures_exact':all(c['checks']['original_structure_exact'] for c in checked),
        'all_current_displays_and_tags_exact':all(c['checks']['current_display_exact'] and c['checks']['visible_tags_exact'] for c in checked),
        'all_registry_numbers_exact':all(c['checks']['theorem_number_exact'] for c in checked),
        'issues':issues,'records':checked}
(base/'independent-ledger-check.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({k:v for k,v in result.items() if k!='records'},ensure_ascii=False,indent=2))
assert total_tags==192,total_tags
assert not issues,issues
