from pathlib import Path
import runpy,re
P=runpy.run_path('scripts/proof-source-audit.py');E=runpy.run_path('tmp/metaproof-audit/edit_rows.py')
path=Path('tex/B28-isomorphism-examples.tex');s=path.read_text(encoding='utf-8');t=P['mask_comments'](s);specs={}
for r in P['rows'](t):
 f=s[slice(*r.args[-2])];rea=s[slice(*r.args[-1])];d=s[slice(*r.opts[0])];line=s.count('\n',0,r.start)+1
 if '; All-Einführung.' in rea:
  m=re.fullmatch(r'\\forall\s+([a-z](?:,[a-z])*)\\in ([AB])\\;\((.*)\)',f)
  if not m:raise ValueError((line,f))
  vs=m[1].split(',');carrier=m[2];matrix=m[3]
  ref=P['references'](rea)[0];key=rea[slice(*ref.args[0])];prem=rea[slice(*ref.args[1])]
  labels=[f'q{line}_{v}' for v in vs];nd=','.join(filter(None,[d,*('@'+x for x in labels)]));body=f'b{line}'
  rows=[{'id':name,'deps':'@'+name,'formula':v+r'\in '+carrier,'reason':r'\rA'} for name,v in zip(labels,vs)]
  inf=rea[ref.start:ref.end]
  a,b=ref.args[1];inf=inf[:a-ref.start]+','.join([prem,*('@'+x for x in labels)])+inf[b-ref.start:]
  rows.append({'id':body,'deps':nd,'formula':matrix,'reason':inf})
  rule='@'+body
  for name in reversed(labels):rule=rf'\rUI{{\rRI{{@{name},{rule}}}}}'
  rows.append({'formula':f,'deps':d,'reason':rule});specs[line]=rows
 m=re.search(r'All-Elimination aus (\d+),(\d+)\}\}$',rea)
 if m:specs[line]=[{'reason':rf'\rRE{{\rUE{{{m[1]}}},{m[2]}}}'}]
 if rea.endswith('All-Elimination in 11}}'):specs[line]=[{'reason':r'\rRE{\rUE{11},12}'}]
 # Endomorphism carriers are a right-associated three-part conjunction.
 for suffix,replacement in [('Konjunktionselimination in 13}}',r'\rAEa{13}' if f.startswith(r'\SemigroupAlg{\operatorname{End}') else r'\rAEa{\rAEb{13}}' if f.startswith(r'\operatorname{Aut}') else r'\rAEb{\rAEb{13}}'),('Konjunktionselimination in 14}}',r'\rAEa{14}')]:
  if rea.endswith(suffix):specs[line]=[{'reason':replacement}]
E['apply'](path,specs,'b28-stage2')
