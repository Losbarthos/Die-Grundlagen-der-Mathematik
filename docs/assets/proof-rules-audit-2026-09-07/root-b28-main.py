from pathlib import Path
import runpy,re
P=runpy.run_path('scripts/proof-source-audit.py');E=runpy.run_path('tmp/metaproof-audit/edit_rows.py')
path=Path('Bd. 28 - Halbgruppen.tex');s=path.read_text(encoding='utf-8');t=P['mask_comments'](s);specs={}
for r in P['rows'](t):
 rea=s[slice(*r.args[-1])];f=s[slice(*r.args[-2])];line=s.count('\n',0,r.start)+1
 if 'Allgemeinheit von' in rea:
  point=r'''\begin{aligned}[t]
    &\SemigroupCoordinateMap{A}{\star}{e}(x\star y)\\[-2pt]
    &\quad=\SemigroupCoordinateMap{A}{\star}{e}(x)
      \SemigroupCoordinateProductOp{A}{\star}{e}
      \SemigroupCoordinateMap{A}{\star}{e}(y)
    \end{aligned}'''
  specs[line]=[
   {'id':'coordx','deps':'@coordx','formula':r'x\in A','reason':r'\rA'},
   {'id':'coordy','deps':'@coordy','formula':r'y\in A','reason':r'\rA'},
   {'id':'coordproduct','deps':'1,@coordx,@coordy','formula':point,'reason':r'\FormulaRefAuto{SemigroupCoordinateIsoOperationAxiom}[ax]{1,@coordx,@coordy}'},
   {'reason':r'\rUI{\rRI{@coordx,\rUI{\rRI{@coordy,@coordproduct}}}}'}]
E['apply'](path,specs,'b28-main-coordinate')
s=path.read_text(encoding='utf-8');start=s.index(r'\begin{tabproofwide}',s.index('}{MogiljanskajaArgumentM10EtaFixedPart}'))
end=s.index(r'\end{tabproofwide}',start)+len(r'\end{tabproofwide}')
s=s[:start]+r'''\begin{tabproofwide}
  \proofstepwidestar[]{c_0\in P}{\FormulaRefAuto{MogiljanskajaDPrimeDef}[def]}
  \proofstepwidestar[]{P\neq\varnothing}{\FormulaRefAuto{a\in A\vdash A\neq\varnothing}[thm]{1}}
  \proofstepwidestar[]{\varnothing\notin\mathcal C}{%
    \FormulaRefAuto{CoreFamilyMembership}[thm]{2},
    \FormulaRefAuto{MogiljanskajaReserveMapsDef}[def]}
  \proofstepwidestar[]{\varnothing\in\mathcal O}{\FormulaRefAuto{MogiljanskajaReserveMapsDef}[def]{3}}
  \proofstepwidestar[]{\eta(\varnothing)=\varnothing}{\FormulaRefAuto{MogiljanskajaReserveMapsDef}[def]{4}}
  \proofstepwidestar[6]{K\in\powerset(D)}{\rA}
  \proofstepwidestar[7]{K\notin\mathcal C}{\rA}
  \proofstepwidestar[6,7]{K\in\mathcal O}{\FormulaRefAuto{MogiljanskajaReserveMapsDef}[def]{6,7}}
  \proofstepwidestar[6,7]{\eta(K)=K}{\FormulaRefAuto{MogiljanskajaReserveMapsDef}[def]{8}}
  \proofstepwidestarbreak[]{\forall K\in\powerset(D)\,
    (K\notin\mathcal C\rightarrow\eta(K)=K)}{\rUI{\rRI{6,\rRI{7,9}}}}
  \proofstepwidestarbreak[]{\eta(\varnothing)=\varnothing\land
    \forall K\in\powerset(D)\,
      (K\notin\mathcal C\rightarrow\eta(K)=K)}{\rAI{5,10}}
\end{tabproofwide}'''+s[end:]
path.write_text(s,encoding='utf-8',newline='\n')
