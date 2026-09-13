"""Apply reviewed intermediate proof lines without changing mathematical numbers.

Specs are keyed by the original source line of a proof row. Each lift gives an
exact nested reference, its concrete formula, and optionally dependencies. Source
positions are resolved before edits; theorem keys and displayed formulas are
never subjected to proof-index replacement.
"""
from pathlib import Path
import runpy, re
P = runpy.run_path(str(Path(__file__).with_name('proof-source-audit.py')))
mask, rows, reference, group = [P[x] for x in ('mask_comments','rows','reference','group')]


def remap_reason(text, mapping):
    masked=mask(text); protected=[]
    for m in re.finditer(r'\\(?:FormulaRefAuto(?:Fwd)?|ThmRefById|ThmRefByStructure(?:Fwd)?)\b',masked):
        if m[0].startswith('\\Formula'):
            c=reference(masked,m.start())
            # Protect the command, structural/ID key, and selector options.
            protected.append((c.start,c.args[1][0]-1 if len(c.args)>1 else c.end))
        else:
            a,e=group(masked,m.end())
            if a:protected.append((m.start(),e))
    for m in re.finditer(r'\\(?:rAIRepeat|rAIReuse)\b',masked):
        a,e=group(masked,m.end())
        if a:protected.append((m.start(),e))
    for m in re.finditer(r'\\multirow\b',masked):
        a,e=group(masked,m.end())
        if a:
            b,f=group(masked,e)
            protected.append((m.start(),f if b else e))
    for m in re.finditer(r'\\(?:text|textnormal|textrm|operatorname|hyperref|ref|label|ProofAuditIndex)\b',masked):
        a,e=group(masked,m.end())
        if a:protected.append((m.start(),e))
    def replace(m):
        if any(a<=m.start()<b for a,b in protected):return m[0]
        return str(mapping.get(int(m[0]),int(m[0])))
    return re.sub(r'(?<![A-Za-z0-9#_^])\d+(?![A-Za-z0-9])',replace,text)


def apply_lifts(original, specs):
    """Return transformed text and an exact change ledger; do not write files.

    specs: {source_line: [{reference, formula, dependencies?}, ...]}
    Multiple occurrences of the same reference use occurrence=0,1,... if needed.
    A parent lift must precede its children in the spec list only for selecting
    source spans; rendering always sorts children before parents.
    """
    text=mask(original);events=[];edits=[];ledger=[]
    reset_re=r'\\begin\{tabproof(?:wide|paired)?\}|\\proofpart(?:wide|paired)?(?:ind(?:Delta)?R?)?\b'
    for m in re.finditer(reset_re,text):events.append((m.start(),'reset',None))
    for m in re.finditer(r'\\setcounter\{proofstepnr\}\{(\d+)\}',text):events.append((m.start(),'counter',m))
    events.extend((r.start,'row',r) for r in rows(text))
    mapping={};old=0;new=0;pending=False
    for pos,kind,obj in sorted(events,key=lambda x:x[0]):
        if kind=='reset':pending=True;continue
        if kind=='counter':
            old=int(obj[1]);new=mapping.get(old,old);pending=False
            if new!=old:edits.append((obj.start(1),obj.end(1),str(new)))
            continue
        if pending:mapping={};old=0;new=0;pending=False
        row=obj
        if row.name=='proofaxline':
            old+=1;new+=1;mapping[old]=new
            a,b=row.args[0];before=original[a:b];after=remap_reason(before,mapping)
            if before!=after:edits.append((a,b,after))
            continue
        numbered=not row.star and row.name not in {'proofstepstar','proofstepstarwide'}
        if numbered:old+=1
        line=text.count('\n',0,row.start)+1
        selected=specs.get(line,[])
        a,b=row.args[-1];reason=original[a:b]
        depspan=row.opts[0] if row.opts else row.args[0] if row.name in {'proofstep','proofstepstar','proofstepstarwide'} else None
        deps=original[slice(*depspan)] if depspan else ''
        located=[]
        for spec in selected:
            needle=spec['reference'];starts=[];q=0
            haystack=reason
            if needle not in haystack:
                haystack=mask(reason);needle=mask(needle)
            while True:
                q=haystack.find(needle,q)
                if q<0:break
                starts.append(q);q+=1
            occurrence=spec.get('occurrence',0)
            if occurrence>=len(starts):
                raise ValueError(f'Lift reference missing at line {line}: {needle}')
            x=starts[occurrence];located.append((x,x+len(needle),spec))
        inserted=[];replaced=[]
        # Innermost applications precede their parent applications.
        for x,y,spec in sorted(located,key=lambda t:(t[1]-t[0],t[0])):
            new+=1;local=reason[x:y]
            inner=[(u-x,v-x,rf'\ProofAuditIndex{{{n}}}') for u,v,n in replaced if x<=u and v<=y]
            outermost=[e for e in inner if not any(f[0]<=e[0] and e[1]<=f[1] and f!=e for f in inner)]
            for u,v,value in sorted(outermost,reverse=True):local=local[:u]+value+local[v:]
            # Newly allocated indices are protected while old references remap.
            local=remap_reason(local,mapping)
            local=re.sub(r'\\ProofAuditIndex\{(\d+)\}',r'\1',local)
            newdeps=remap_reason(spec.get('dependencies',deps),mapping)
            formula=spec['formula']
            if row.name in {'proofstep','proofstepstar'}:
                statement=f'\\proofstep{{{newdeps}}}{{{formula}}}{{%\n      {local}}}'
            elif row.name=='proofsteppaired':
                statement=f'\\proofsteppaired[{newdeps}]{{{formula}}}{{%\n      {local}}}'
            else:
                statement=f'\\proofstepwidestar[{newdeps}]{{{formula}}}{{%\n      {local}}}'
            inserted.append(statement);replaced.append((x,y,new))
            ledger.append({'line':line,'old_row':old,'new_row':new,'formula':formula,'reference':spec['reference']})
        if numbered:new+=1;mapping[old]=new
        # First remap old indices, then insert new indices so collisions cannot
        # accidentally reinterpret an inserted index as an old one.
        spans=[e for e in replaced if not any(f[0]<=e[0] and e[1]<=f[1] and f!=e for f in replaced)]
        newreason=reason
        for x,y,n in sorted(spans,reverse=True):
            newreason=newreason[:x]+rf'\ProofAuditIndex{{{n}}}'+newreason[y:]
        newreason=remap_reason(newreason,mapping)
        newreason=re.sub(r'\\ProofAuditIndex\{(\d+)\}',r'\1',newreason)
        if newreason!=reason:edits.append((a,b,newreason))
        if depspan:
            newdeps=remap_reason(deps,mapping)
            if newdeps!=deps:edits.append((*depspan,newdeps))
        if inserted:
            prefix=original[original.rfind('\n',0,row.start)+1:row.start]
            indent=prefix if not prefix.strip() else '  '
            edits.append((row.start,row.start,('\n'+indent).join(inserted)+'\n'+indent))
    used={x['line'] for x in ledger}
    missing=set(specs)-used
    if missing:raise ValueError(f'No proof rows found for specs: {sorted(missing)}')
    for a,b,value in sorted(edits,key=lambda x:(x[0],x[1]),reverse=True):
        original=original[:a]+value+original[b:]
    return original,ledger
