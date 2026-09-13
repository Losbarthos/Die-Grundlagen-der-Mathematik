from pathlib import Path
import runpy
P=runpy.run_path('scripts/proof-source-audit.py');E=runpy.run_path('tmp/metaproof-audit/edit_rows.py')
path=Path('tex/B28-isomorphism-examples.tex');s=path.read_text(encoding='utf-8');t=P['mask_comments'](s);specs={}
for r in P['rows'](t):
    f=s[slice(*r.args[-2])];reason=s[slice(*r.args[-1])];line=s.count('\n',0,r.start)+1
    if 'Konjunktions-Elimination aus 27' in reason and f==r'h[f[X]]=X':
        specs[line]=[{'reason':r'\rAEa{\rAEb{27}}'}]
    if 'Definition der nichtleeren Potenzmenge aus 16' in reason and f==r'f[X]\subseteq B':
        specs[line]=[{'formula':r'f[X]\subseteq B\land f[X]\neq\varnothing','reason':r'\FormulaRefAuto{NonemptyPowersetMembership}[thm]{16}','id':'image_properties'}, {'reason':r'\rAEa{@image_properties}'}]
    if 'Definition der nichtleeren Potenzmenge aus 16' in reason and f==r'f[X]\neq\varnothing':
        specs[line]=[{'reason':r'\rAEb{@image_properties}'}]
assert len(specs)==3,len(specs)
E['apply'](path,specs,'b28-generated-simple')
