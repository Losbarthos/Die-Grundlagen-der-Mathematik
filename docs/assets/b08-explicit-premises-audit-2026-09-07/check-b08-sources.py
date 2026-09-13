"""Structural check supporting, not replacing, the recorded mathematical reviews."""
from pathlib import Path
from collections import Counter
import hashlib,json,re,runpy,sys

root=Path.cwd(); here=Path(__file__).resolve().parent
P=runpy.run_path(str(root/'scripts/proof-source-audit.py'))
source=root/'Bd. 08 - Bijektive Funktionen.tex'
s=source.read_text(encoding='utf-8-sig'); mask=P['mask_comments'](s)
old=(here/'B08-before.tex').read_text(encoding='utf-8-sig')
before_registry=(here/'B08-before.registry.tsv').read_text(encoding='utf-8')
numbers=[]
for line in before_registry.splitlines():
    c=line.split('\t')
    if len(c)>3 and c[0]=='1' and c[1].startswith('thm:auto:') and c[3] not in numbers:numbers.append(c[3])

def declarations(text):
    masked=P['mask_comments'](text); result=[]
    arities={'FormulaThmDelta':2,'FormulaThmDeltaK':3,'FormulaThmDeltaR':3,'FormulaThmDeltaKR':4}
    for m in re.finditer(r'\\FormulaThm[A-Za-z]*\b',masked):
        assert m[0][1:] in arities,m[0]
        c=P['call'](masked,m.start(),arities[m[0][1:]])
        vals=[text[slice(*v)] for v in c.args]
        ident=vals[2] if c.name.endswith('KR') else vals[1] if c.name.endswith('K') else None
        structure=vals[1] if c.name.endswith('R') else vals[0]
        result.append(dict(macro=c.name,line=text.count('\n',0,c.start)+1,
            title=text[slice(*c.opts[0])] if c.opts else '',display=vals[0],
            structural_formula=structure,id=ident,delta=vals[-1]))
    return result

def compact(text):return re.sub(r'\s+','',P['mask_comments'](text))
initial=declarations(old); current=declarations(s)
assert len(initial)==len(current)==len(numbers)==94,(len(initial),len(current),len(numbers))
inverse=json.loads((here/'inverse-migration.json').read_text(encoding='utf-8'))
composition=json.loads((here/'composition-migration.json').read_text(encoding='utf-8'))
changes={v['number']:dict(id=v['id'],formula=v['new_formula']) for v in inverse}
changes.update({v['number']:dict(id=v['new_id'],formula=v['new_structural_formula']) for v in composition if v['number']!='8.3.4.1'})
assert len(changes)==26
errors=[]
for n,a,b in zip(numbers,initial,current):
    b['number']=n
    b['statement_changed']=n in changes
    if r'\DeltaPrem' in P['mask_comments'](b['delta']):errors.append(f'{n}: theorem DeltaPrem remains')
    b['title_added']=not a['title'] and bool(b['title'])
    if a['title'] and a['title']!=b['title']:errors.append(f'{n}: changed existing title')
    if n in changes:
        q=changes[n]
        if b['id']!=q['id'] or compact(b['structural_formula'])!=compact(q['formula']):errors.append(f'{n}: migration differs')
        if r'\vdash' not in b['structural_formula']:errors.append(f'{n}: missing explicit sequent')
    elif compact(a['display'])!=compact(b['display']):errors.append(f'{n}: unexpected statement change')
helpers=re.findall(r'\\proofpart(?:wide|paired)?ind(?:Delta)?R?\b',mask)
assert len(helpers)==41,len(helpers)
ids=[b['id'] for b in current if b['id']]
if len(ids)!=len(set(ids)):errors.append('Duplicate source IDs')
if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f]',s):errors.append('Control character')

registry_checks=[]
if '--with-registry' in sys.argv:
    registry=(root/'registry/_B08.registry.tsv').read_text(encoding='utf-8')
    after_numbers=[]
    for line in registry.splitlines():
        c=line.split('\t')
        if len(c)>3 and c[0]=='1' and c[1].startswith('thm:auto:') and c[3] not in after_numbers:after_numbers.append(c[3])
    if numbers!=after_numbers:errors.append('Theorem numbering changed')
    for n,q in changes.items():
        expected=f"ID\t{q['id']}\ttheorem\tthm:auto:{n}"
        valid=expected in registry.splitlines()
        registry_checks.append(dict(number=n,id=q['id'],passed=valid))
        if not valid:errors.append(f'{n}: missing or wrongly numbered registry ID')

result=dict(main_theorems=94,registered_helpers=41,changed_statements=26,
    mathematical_theorem_delta_premises=0 if not any('DeltaPrem' in e for e in errors) else None,
    source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    registry_checks=registry_checks,errors=errors,theorems=current)
(here/'current-source-validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in result.items() if k not in ('theorems','registry_checks')},ensure_ascii=False))
sys.exit(bool(errors))
