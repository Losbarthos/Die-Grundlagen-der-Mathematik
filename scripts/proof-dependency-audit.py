"""Audit printed open assumptions and backward line citations in proof tables.

This checks dependency bookkeeping, not the validity of formulas or theorem
instantiations. Mathematical proof review remains a separate requirement.
"""
from pathlib import Path
import re,runpy
ROOT=Path(__file__).resolve().parents[1]
P=runpy.run_path(str(ROOT/'scripts/proof-source-audit.py'))

def split(s):
    out=[]; start=depth=0
    for i,c in enumerate(s):
        if c=='{':depth+=1
        elif c=='}':depth-=1
        elif c==',' and depth==0:out.append(s[start:i].strip());start=i+1
    out.append(s[start:].strip())
    return out

def deps(s, known, n):
    s=s.strip()
    if s.isdigit():
        i=int(s)
        if i not in known:raise ValueError(f'line {i} unavailable before {n}')
        return known[i]
    if s==r'\rA':return {n}
    if s==r'\rII':return set()
    if s.startswith(r'\FormulaRefAuto'):
        c=P['reference'](s,0)
        if c.end!=len(s):raise NotImplementedError(s)
        args=split(s[slice(*c.args[1])]) if len(c.args)>1 else []
        return set().union(*(deps(a,known,n) for a in args))
    m=re.match(r'\\(r[A-Za-z]+|UEI|UEE)',s)
    if not m:raise NotImplementedError(s)
    g,end=P['group'](s,m.end())
    if g is None or end!=len(s):raise NotImplementedError(s)
    name=m[1];args=split(s[slice(*g)])
    values=[deps(a,known,n) for a in args]
    result=set().union(*values)
    if name in {'rRI','rCI','rCE'}:
        if len(args)!=2:raise ValueError(f'{name}: expected assumption and conclusion')
        result.discard(int(args[0]))
    elif name=='rOE':
        if len(args)!=5:raise NotImplementedError(s)
        result-= {int(args[1]),int(args[3])}
    elif name in {'rEE','rEEStar','UEE','rUEI','UEI'}:
        result-=set(int(a) for a in args[1:-1])
    elif name=='rIE' and len(args)<2:
        raise ValueError('=E requires an equality and a source formula')
    return result

def check(path):
    text=P['mask_comments'](path.read_text(encoding='utf-8-sig'))
    events=[]
    for m in re.finditer(r'\\begin\{tabproof(?:wide|paired)?\}|\\proofpart(?:wide|paired)?(?:ind(?:Delta)?R?)?\b',text):events.append((m.start(),'reset',None))
    for m in re.finditer(r'\\setcounter\{proofstepnr\}\{(\d+)\}',text):events.append((m.start(),'counter',m))
    events.extend((r.start,'row',r) for r in P['rows'](text))
    known={};n=0;checked=skipped=errors=0;pending=False
    for pos,kind,obj in sorted(events,key=lambda x:x[0]):
        if kind=='reset':pending=True;continue
        if kind=='counter':n=int(obj[1]);pending=False;continue
        if pending:known={};n=0;pending=False
        n+=1;row=obj;line=text.count('\n',0,row.start)+1
        reason=text[slice(*row.args[-1])].strip()
        if row.opts:declared=set(map(int,re.findall(r'\d+',text[slice(*row.opts[0])])))
        elif row.name in {'proofstep','proofstepstar','proofstepstarwide'}:declared=set(map(int,re.findall(r'\d+',text[slice(*row.args[0])])))
        else:declared=set()
        try:
            actual=deps(reason,known,n);checked+=1
            if actual!=declared:
                errors+=1;print(f'{path.name}:{line} row {n}: printed {sorted(declared)} vs inferred {sorted(actual)}; {reason}')
            known[n]=actual
        except NotImplementedError:
            skipped+=1;known[n]=declared
            print(f'{path.name}:{line} row {n}: manual dependency review needed: {reason}')
        except ValueError as e:
            errors+=1;known[n]=declared;print(f'{path.name}:{line} row {n}: {e}; {reason}')
    print(path.name,'checked',checked,'manual',skipped,'errors',errors)
    return errors+skipped

if __name__=='__main__':
    import sys
    paths=[Path(x) for x in sys.argv[1:]] or [ROOT/'tex/b41/differences'/n for n in ['product-example.tex','product-integers.tex','maximum-counterexample.tex','necessary-conditions.tex']]
    raise SystemExit(bool(sum(check(p) for p in paths)))
