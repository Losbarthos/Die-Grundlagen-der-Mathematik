from pathlib import Path
from named_proof import Proof
p=Proof();a=p.add
a('iso',r'f:A\cong B',r'\rA')
a('e',r'e\in A',r'\rA')
a('z',r'z\in A',r'\rA')
a('sg',r'\SemigroupAlg{A}{\star}',r'\FormulaRefAuto{SemigroupIsoSource}[thm]{@iso}')
a('f',r'f:A\to B',r'\FormulaRefAuto{SemigroupIsoFunction}[thm]{@iso}')
a('bij',r'f:A\bij B',r'\FormulaRefAuto{SemigroupIsoBijectiveAxiom}[ax]{@iso}')
a('hinv',r'h:B\bij A',r'\FormulaRefAuto{SemigroupIsoInverseCarrier}[thm]{@iso}')
a('h',r'h:B\to A',r'\FormulaRefAuto{Bijektive Funktion}[def]{@hinv}')
for k in ('e','z'):
    def add(label,formula,reason,discharge=()):
        # Prefix local labels, while global premises keep their names.
        import re
        reason=re.sub(r'@([A-Za-z_][A-Za-z_0-9]*)',lambda m:'@'+(m[1] if m[1] in ('iso','sg','f','bij','h','hinv','e','z') else k+'_'+m[1]),reason)
        a(k+'_'+label,formula,reason,tuple(k+'_'+x for x in discharge))
    qx='x' if k=='e' else k
    qy='y' if k=='e' else 'f(z)'
    qt='h(y)' if k=='e' else k
    qfx='f(x)' if k=='e' else 'f(z)'
    source=rf'\forall x\in A\;({k}x={qx}\land x{k}={qx})'
    target=rf'\forall y\in B\;(f({k})y={qy}\land yf({k})={qy})'
    add('source',source,r'\rA')
    add('y',r'y\in B',r'\rA')
    add('hy',r'h(y)\in A',r'\FormulaRefAuto{F\colon A\to B\dsep x\in A\vdash F(x)\in B}[thm]{@h,@y}')
    add('hyvalue',r'f(h(y))=y',r'\FormulaRefAuto{F\colon A\bij B\dsep y\in B\vdash F(F^{-1}(y))=y}[thm]{@bij,@y}')
    add('at_hy',rf'{k}h(y)={qt}\land h(y){k}={qt}',r'\rRE{\rUE{@source},@hy}')
    add('left_hy',rf'{k}h(y)={qt}',r'\rAEa{@at_hy}')
    add('right_hy',rf'h(y){k}={qt}',r'\rAEb{@at_hy}')
    add('left_op',rf'f({k}h(y))=f({k})f(h(y))',rf'\FormulaRefAuto{{SemigroupIsoOperation}}[thm]{{@iso,@{k},@hy}}')
    add('right_op',rf'f(h(y){k})=f(h(y))f({k})',rf'\FormulaRefAuto{{SemigroupIsoOperation}}[thm]{{@iso,@hy,@{k}}}')
    add('left_eq',rf'{qy}=f({k})y',r'\rIE{@left_hy,@hyvalue,@left_op}')
    add('right_eq',rf'{qy}=yf({k})',r'\rIE{@right_hy,@hyvalue,@right_op}')
    add('left_result',rf'f({k})y={qy}',r'\FormulaRefAuto{a=b\vdash b=a}[thm]{@left_eq}')
    add('right_result',rf'yf({k})={qy}',r'\FormulaRefAuto{a=b\vdash b=a}[thm]{@right_eq}')
    add('y_result',rf'f({k})y={qy}\land yf({k})={qy}',r'\rAI{@left_result,@right_result}')
    add('all_y',target,r'\rUI{\rRI{@y,@y_result}}',('y',))
    add('forward',rf'\begin{{aligned}}[t]&({source})\\[-2pt]&\quad\rightarrow({target})\end{{aligned}}',r'\rRI{@source,@all_y}',('source',))
    add('target',target,r'\rA')
    add('x',r'x\in A',r'\rA')
    add('fx',r'f(x)\in B',r'\FormulaRefAuto{F\colon A\to B\dsep x\in A\vdash F(x)\in B}[thm]{@f,@x}')
    add('at_fx',rf'f({k})f(x)={qfx}\land f(x)f({k})={qfx}',r'\rRE{\rUE{@target},@fx}')
    add('left_fx',rf'f({k})f(x)={qfx}',r'\rAEa{@at_fx}')
    add('right_fx',rf'f(x)f({k})={qfx}',r'\rAEb{@at_fx}')
    add('kx',rf'{k}x\in A',rf'\FormulaRefAuto{{SemigroupClosureAxiom}}[ax]{{@sg,@{k},@x}}')
    add('xk',rf'x{k}\in A',rf'\FormulaRefAuto{{SemigroupClosureAxiom}}[ax]{{@sg,@x,@{k}}}')
    add('left_x_op',rf'f({k}x)=f({k})f(x)',rf'\FormulaRefAuto{{SemigroupIsoOperation}}[thm]{{@iso,@{k},@x}}')
    add('right_x_op',rf'f(x{k})=f(x)f({k})',rf'\FormulaRefAuto{{SemigroupIsoOperation}}[thm]{{@iso,@x,@{k}}}')
    add('left_image_eq',rf'f({k}x)={qfx}',r'\rIE{@left_fx,@left_x_op}')
    add('right_image_eq',rf'f(x{k})={qfx}',r'\rIE{@right_fx,@right_x_op}')
    arg='x' if k=='e' else k
    add('left_reflect',rf'{k}x={qx}\leftrightarrow f({k}x)={qfx}',rf'\FormulaRefAuto{{SemigroupIsoEqualityReflection}}[thm]{{@iso,@kx,@{arg}}}')
    add('right_reflect',rf'x{k}={qx}\leftrightarrow f(x{k})={qfx}',rf'\FormulaRefAuto{{SemigroupIsoEqualityReflection}}[thm]{{@iso,@xk,@{arg}}}')
    add('left_x',rf'{k}x={qx}',r'\rRE{\rLREb{@left_reflect},@left_image_eq}')
    add('right_x',rf'x{k}={qx}',r'\rRE{\rLREb{@right_reflect},@right_image_eq}')
    add('x_result',rf'{k}x={qx}\land x{k}={qx}',r'\rAI{@left_x,@right_x}')
    add('all_x',source,r'\rUI{\rRI{@x,@x_result}}',('x',))
    add('backward',rf'\begin{{aligned}}[t]&({target})\\[-2pt]&\quad\rightarrow({source})\end{{aligned}}',r'\rRI{@target,@all_x}',('target',))
    add('result',rf'\begin{{aligned}}[t]&({source})\\[-2pt]&\quad\leftrightarrow({target})\end{{aligned}}',r'\rLRI{@forward,@backward}')
path=Path('tex/B28-isomorphism-examples.tex');s=path.read_text(encoding='utf-8')
start=s.index('\n',s.index('[SemigroupIsoIdentityZeroConditions]'))+1;end=s.index(r'\closeproofpartwideindR',start)
backup=Path('tmp/metaproof-audit/b28-neutral-body-before.tex')
if not backup.exists():backup.write_text(s[start:end],encoding='utf-8')
path.write_text(s[:start]+p.render()+s[end:],encoding='utf-8',newline='\n')
print('Neutral and zero transport:',len(p.rows),'steps')
