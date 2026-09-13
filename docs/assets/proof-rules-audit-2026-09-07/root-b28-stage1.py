from pathlib import Path
import runpy,re,json
P=runpy.run_path('scripts/proof-source-audit.py')
E=runpy.run_path('scripts/proof-edit-tools.py')
path=Path('tex/B28-isomorphism-examples.tex')
s=Path('tmp/metaproof-audit/B28-examples-before.tex').read_text(encoding='utf-8-sig'); t=P['mask_comments'](s)
events=[]
for m in re.finditer(r'\\begin\{tabproof(?:wide|paired)?\}|\\proofpart(?:wide|paired)?(?:ind(?:Delta)?R?)?\b',t): events.append((m.start(),'reset',None))
for r in P['rows'](t):events.append((r.start,'row',r))
parts=[]; part=[]
for _,kind,r in sorted(events):
 if kind=='reset':
  if part:parts.append(part)
  part=[]
 else:part.append(r)
if part:parts.append(part)
edits=[];ledger=[]

def formula(r):return s[slice(*r.args[-2])]
def reason(r):return s[slice(*r.args[-1])]
def deps(r):return s[slice(*r.opts[0])] if r.opts else ''
def split_assumption(f):
 # The comma notation is right-associated conjunction (B01).
 pieces=re.split(r'\\,,\\quad\s*',f)
 if len(pieces)==1 and re.match(r'^[a-zA-Z]\\geq1\\land',f):pieces=f.split(r'\land',1)
 out=[]
 for piece in pieces:
  m=re.fullmatch(r"([a-zA-Z](?:')?(?:,[a-zA-Z](?:')?)+)\\in\s*(.+)",piece)
  if m:out.extend(v+r'\in '+m[2] for v in m[1].split(','))
  else:out.append(piece)
 # Several non-carrier assumptions remain one conjunction, matching the
 # antecedent printed after the quantifiers (rather than currying it).
 cut=next((i for i,x in enumerate(out) if not re.match(r"^[a-zA-Z](?:')?\\(?:in|geq)",x)),len(out))
 if cut<len(out)-1:out=out[:cut]+[r'\land '.join(out[cut:])]
 return out

for part in parts:
 oldrows={i:r for i,r in enumerate(part,1)}; ui={}; splits={}; simple={}
 for i,r in oldrows.items():
  rea=reason(r)
  m=re.fullmatch(r'\\text\{\\parbox\[t\]\{\\linewidth\}\{\\raggedright All-(?:Einführung| und Implikationseinführung) aus ([\d,\-]+)\}\}',rea)
  if m and formula(r).startswith(r'\forall'):
   nums=list(map(int,re.findall(r'\d+',m[1]))); end=nums[-1]
   if end>=i:raise ValueError((i,rea))
   before=set(map(int,re.findall(r'\d+',deps(oldrows[end])))); after=set(map(int,re.findall(r'\d+',deps(r))))
   discharge=sorted(before-after)
   if not discharge or any(reason(oldrows[x]).strip()!=r'\rA' for x in discharge):
    continue
   for x in discharge:splits[x]=split_assumption(formula(oldrows[x]))
   ui[i]=(end,discharge)
  # Obvious syntactic rules, reviewed further against their premises below.
  simple_patterns=[
   (r'Gleichheitseinsetzung (?:von )?(\d+) in (\d+)',lambda m:rf'\rIE{{{m[1]},{m[2]}}}'),
   (r'Gleichheitseinsetzung (\d+),(\d+) in (\d+)',lambda m:rf'\rIE{{{m[1]},{m[2]},{m[3]}}}'),
   (r'Implikations-Elimination aus (\d+),(\d+)',lambda m:rf'\rRE{{{m[1]},{m[2]}}}'),
   (r'Äquivalenz(?:einf|einf|einfü)hrung aus (\d+),(\d+)',lambda m:rf'\rLRI{{{m[1]},{m[2]}}}'),
  ]
  bare=re.sub(r'^\\text\{\\parbox\[t\]\{\\linewidth\}\{\\raggedright |\}\}$','',rea)
  if bare=='Reflexivität' and '=' in formula(r):simple[i]=r'\rII'
  for pat,fn in simple_patterns:
   m=re.fullmatch(pat,bare)
   if m:simple[i]=fn(m)
  m=re.fullmatch(r'Konjunktions[- ]?(?:Einführung|einführung) aus (\d+),(\d+),(\d+)',bare)
  if m:simple[i]=rf'\rAI{{{m[1]},\rAI{{{m[2]},{m[3]}}}}}'
  m=re.fullmatch(r'Konjunktion aus (\d+),(\d+),(\d+)',bare)
  if m:simple[i]=rf'\rAI{{{m[1]},\rAI{{{m[2]},{m[3]}}}}}'
  m=re.fullmatch(r'Konjunktions-Elimination aus (\d+)',bare)
  if m:
   src=formula(oldrows[int(m[1])]); want=formula(r)
   if src.startswith(want+r'\land'):simple[i]=rf'\rAEa{{{m[1]}}}'
  if bare=='Äquivalenz-Elimination aus 12,11':simple[i]=r'\rRE{\rLREa{\rAEb{\rAEb{12}}},11}'
  if bare=='Äquivalenz-Elimination aus 29,28':simple[i]=r'\rRE{\rLREb{29},28}'
  if bare=='Äquivalenz-Elimination aus 16,12':simple[i]=r'\rRE{\rLREa{16},12}'
  if bare=='Äquivalenz-Elimination aus 15,16':simple[i]=r'\rRE{\rLREb{15},16}'
  if bare=='Wiederholung 1':simple[i]=r'\rAEa{\rAI{1,1}}'
 # Allocate indices before remapping any text.
 mapping={}; splitnums={}; count=0
 for i,r in oldrows.items():
  if i in splits and len(splits[i])>1:
   splitnums[i]=list(range(count+1,count+len(splits[i])+1));count+=len(splits[i])
  count+=1;mapping[i]=count
 def remap(x):
  protected=[]
  def keep(m):
   protected.append(m[0]);return rf'\ProofAuditIndex{{M{len(protected)-1}}}'
  x=re.sub(r'\\\(.*?\\\)',keep,x,flags=re.S)
  x=x.replace(r'\text{',r'\AuditText{')
  x=E['remap_reason'](x,mapping).replace(r'\AuditText{',r'\text{')
  for n,v in enumerate(protected):x=x.replace(rf'\ProofAuditIndex{{M{n}}}',v)
  return x
 def depmap(x):
  result=[]
  for v in re.findall(r'\d+',x):
   for n in splitnums.get(int(v),[mapping.get(int(v),int(v))]):
    if n not in result:result.append(n)
  return ','.join(map(str,result))
 for i,r in oldrows.items():
  newreason=simple.get(i,reason(r)); newdeps=depmap(deps(r));prefix=''
  if i in splitnums:
   ns=splitnums[i]
   prefix='\n '.join(rf'\proofstepwidestar[{n}]{{{f}}}{{\rA}}' for n,f in zip(ns,splits[i]))+'\n '
   # Each component is recorded once; the original combined row remains usable.
   newreason=rf'\rAIStar{{{",".join(map(str,ns))}}}'
   mappedreason=newreason
  else:mappedreason=remap(newreason)
  if i in ui:
   end,discharge=ui[i];acc=str(mapping[end]);details=[]
   for x in reversed(discharge):
    fs=splits[x];ns=splitnums.get(x,[mapping[x]])
    for f,n in reversed(list(zip(fs,ns))):
     acc=rf'\rRI{{{n},{acc}}}'
     # Membership and natural-index restrictions introduce their variable.
     bound=bool(re.match(r"^(?:[a-zA-Z](?:')?|\\(?:rho|tau|alpha))(?::|\\(?:in|geq))",f))
     if bound:acc=rf'\rUI{{{acc}}}'
     details.append((f,n,bound))
   if re.match(r'\\forall\s+W\\;',formula(r)):acc=rf'\rUI{{{acc}}}'
   mappedreason=acc
   ledger.append({'line':s.count('\n',0,r.start)+1,'old_row':i,'formula':formula(r),'reason':mappedreason,'discharged':details})
  local=s[r.start:r.end]
  changes=[(a-r.start,b-r.start,v) for (a,b),v in [(r.args[-1],mappedreason),(r.opts[0],newdeps)] if s[a:b]!=v]
  for a,b,v in sorted(changes,reverse=True):local=local[:a]+v+local[b:]
  if prefix or local!=s[r.start:r.end]:edits.append((r.start,r.end,prefix+local))
for a,b,v in sorted(edits,reverse=True):s=s[:a]+v+s[b:]
path.write_text(s,encoding='utf-8',newline='\n')
Path('tmp/metaproof-audit/b28-stage1-ui.json').write_text(json.dumps(ledger,ensure_ascii=False,indent=2),encoding='utf-8')
print('Rewritten rows',len(edits),'quantifier conclusions',len(ledger))
