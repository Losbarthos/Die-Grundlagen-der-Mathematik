from pathlib import Path
import runpy,re
P=runpy.run_path('scripts/proof-source-audit.py');E=runpy.run_path('tmp/metaproof-audit/edit_rows.py')
path=Path('tex/B28-isomorphism-examples.tex');s=path.read_text(encoding='utf-8')
# This whole subproof used an unlicensed move of an equivalence under exists.
start=s.index('\n',s.index('[SemigroupIsoImageMembership]'))+1
end=s.index(r'\closeproofpartwideindR',start)
s=s[:start]+r'''  \proofstepwidestar[1]{f:A\cong B}{\rA}
  \proofstepwidestar[2]{U\subseteq A}{\rA}
  \proofstepwidestar[3]{x\in A}{\rA}
  \proofstepwidestar[1]{f:A\to B}{\FormulaRefAuto{SemigroupIsoFunction}[thm]{1}}
  \proofstepwidestar[5]{x\in U}{\rA}
  \proofstepwidestar[1,2,5]{f(x)\in f[U]}{\FormulaRefAuto{C\subseteq A\dsep F\colon A\to B\dsep x\in C\vdash F(x)\in F[C]}[thm]{2,4,5}}
  \proofstepwidestar[1,2]{x\in U\rightarrow f(x)\in f[U]}{\rRI{5,6}}
  \proofstepwidestar[8]{f(x)\in f[U]}{\rA}
  \proofstepwidestar[1,2,8]{\exists z\in U\;(f(x)=f(z))}{\FormulaRefAuto{C\subseteq A\dsep F\colon A\to B\dsep y\in F[C]\vdash\exists x\in C\,y=F(x)}[thm]{2,4,8}}
  \proofstepwidestar[10]{z\in U\land f(x)=f(z)}{\rA}
  \proofstepwidestar[10]{z\in U}{\rAEa{10}}
  \proofstepwidestar[10]{f(x)=f(z)}{\rAEb{10}}
  \proofstepwidestar[2,10]{z\in A}{\FormulaRefAuto{A\subseteq B,\,x\in A\vdash x\in B}[thm]{2,11}}
  \proofstepwidestar[1,2,3,10]{x=z\leftrightarrow f(x)=f(z)}{\FormulaRefAuto{SemigroupIsoEqualityReflection}[thm]{1,3,13}}
  \proofstepwidestar[1,2,3,10]{x=z}{\rRE{\rLREb{14},12}}
  \proofstepwidestar[1,2,3,10]{x\in U}{\rIE{15,11}}
  \proofstepwidestar[1,2,3,8]{x\in U}{\rEE{9,10,16}}
  \proofstepwidestar[1,2,3]{f(x)\in f[U]\rightarrow x\in U}{\rRI{8,17}}
  \proofstepwidestar[1,2,3]{x\in U\leftrightarrow f(x)\in f[U]}{\rLRI{7,18}}
''' +s[end:]
path.write_text(s,encoding='utf-8',newline='\n')
t=P['mask_comments'](s);specs={}
def row(reason,formula=None,deps=None,id=None):return {k:v for k,v in locals().items() if v is not None}
for r in P['rows'](t):
 f=s[slice(*r.args[-2])];rea=s[slice(*r.args[-1])];d=s[slice(*r.opts[0])];line=s.count('\n',0,r.start)+1
 if 'Bildzeuge: jedes Element' in rea:
  specs[line]=[
   row(r'\rAI{2,15}',r'U\subseteq A\land U\neq\varnothing',id='un'),
   row(r'\FormulaRefAuto{NonemptyPowersetMembership}[thm]{@un}',r'U\in\PowNE A',id='up'),
   row(r'\FormulaRefAuto{NonemptyDirectImage}[thm]{4,@up}',r'f[U]\in\PowNE B',id='fp'),
   row(r'\FormulaRefAuto{NonemptyPowersetMembership}[thm]{@fp}',r'f[U]\subseteq B\land f[U]\neq\varnothing',id='fn'),
   row(r'\rAEb{@fn}')]
 if 'Ein Bildzeuge gehört' in rea:
  specs[line]=[
   row(r'\rAI{10,18}',r'f[U]\subseteq B\land f[U]\neq\varnothing',id='fnback'),
   row(r'\FormulaRefAuto{NonemptyPowersetMembership}[thm]{@fnback}',r'f[U]\in\PowNE B',id='fpback'),
   row(r'\FormulaRefAuto{NonemptyDirectImage}[thm]{7,@fpback}',r'h[f[U]]\in\PowNE A',id='hp'),
   row(r'\FormulaRefAuto{NonemptyPowersetMembership}[thm]{@hp}',r'h[f[U]]\subseteq A\land h[f[U]]\neq\varnothing',id='hn'),
   row(r'\rIE{14,\rAEb{@hn}}')]
 if 'Bilddefinition; Zeuge aus 19' in rea:
  specs[line]=[row(r'\FormulaRefAuto{C\subseteq A\dsep F\colon A\to B\dsep x\in C\vdash F(x)\in F[C]}[thm]{10,4,19}')]
 if 'Teilträgerzugriff aus 10,17,18' in rea:
  left,right=f.split(r'\in')[0].split(',');left=left.strip();right=right.strip()
  members=[left+r'\in A',right+r'\in A']
  if left=='h(u)' and right=='h(v)':rules=[r'\FormulaRefAuto{A\subseteq B,\,x\in A\vdash x\in B}[thm]{10,17}',r'\FormulaRefAuto{A\subseteq B,\,x\in A\vdash x\in B}[thm]{10,18}']
  elif left=='h(b)':rules=[r'\rAEa{\rAI{17,17}}',r'\FormulaRefAuto{A\subseteq B,\,x\in A\vdash x\in B}[thm]{10,18}']
  else:rules=[r'\FormulaRefAuto{A\subseteq B,\,x\in A\vdash x\in B}[thm]{10,17}',r'\rAEa{\rAI{18,18}}']
  specs[line]=[row(rules[0],members[0],id='carrierone'),row(rules[1],members[1],id='carriertwo'),row(r'\rAI{@carrierone,@carriertwo}')]
 if rea=='13,15,16' and f.endswith(r'\in B'):
  a,b=f.split(r'\in')[0].split(',')
  if a=='u' and b=='v':specs[line]=[row(r'\FormulaRefAuto{A\subseteq B,\,x\in A\vdash x\in B}[thm]{13,15}',a+r'\in B',id='targetone'),row(r'\FormulaRefAuto{A\subseteq B,\,x\in A\vdash x\in B}[thm]{13,16}',b+r'\in B',id='targettwo'),row(r'\rAI{@targetone,@targettwo}')]
  else:
   specs[line]=[row(r'\FormulaRefAuto{A\subseteq B,\,x\in A\vdash x\in B}[thm]{13,16}',r'u\in B',id='targetu'),row(r'\rAI{15,@targetu}' if a=='b' else r'\rAI{@targetu,15}')]
 if 'Einermengenzeuge' in rea and f==r'\{a\}\neq\varnothing':specs[line]=[row(r'\FormulaRefAuto{a\in\{a\}}[thm]',r'a\in\{a\}',id='singletonw'),row(r'\FormulaRefAuto{a\in A\vdash A\neq\varnothing}[thm]{@singletonw}')]
 if ('Bilddefinition: genau der Bildwert' in rea or 'Bilddefinition mit einzigem Zeugen' in rea) and f==r'f[\{a\}]=\{f(a)\}':specs[line]=[row(r'\FormulaRefAuto{x\in A\dsep F\colon A\to B\vdash F[\{x\}]=\{F(x)\}}[thm]{8,4}')]
 if rea.endswith('Elementzeuge 13}}') and f==r'eAe\neq\varnothing':specs[line]=[row(r'\FormulaRefAuto{a\in A\vdash A\neq\varnothing}[thm]{13}')]
E['apply'](path,specs,'b28-stage3')
