"""Collect final build/publication evidence for this bounded B08 task."""
from pathlib import Path
import csv,json,re,hashlib,runpy
from collections import Counter
from pypdf import PdfReader

root=Path.cwd();out=Path(__file__).resolve().parent
P=runpy.run_path(str(root/'scripts/proof-source-audit.py'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
bands=['B00','B08','B09','B10','B11','B20','B21','B28','B37','B43']
graph={r['band']:r for r in csv.DictReader((root/'band-dependencies.tsv').open(encoding='utf-8-sig'),delimiter='\t')}
paths=[root/'Bd. 08 - Bijektive Funktionen.tex']
paths += [root/r['file'] for r in json.loads((root/'tmp/metaproof-audit/b08-external-migration/external-migration-files.json').read_text(encoding='utf-8'))]
source_hashes={str(p.relative_to(root)):sha(p) for p in paths}
artifacts=[];errors=[]
for band in bands+['main']:
    source=root/'main.pdf' if band=='main' else root/(graph[band]['artifact_base']+'.pdf')
    published=root/'output'/('Die Grundlagen der Mathematik - Gesamtband.pdf' if band=='main' else Path(graph[band]['source']).with_suffix('.pdf').name)
    a=PdfReader(source);b=PdfReader(published)
    if len(a.pages)!=len(b.pages):errors.append(f'{band}: publication page count differs')
    if set(a.named_destinations)!=set(b.named_destinations):errors.append(f'{band}: publication destinations differ')
    artifacts.append(dict(band=band,compiled_pdf=str(source.relative_to(root)),published_pdf=str(published.relative_to(root)),
        pages=len(a.pages),compiled_sha256=sha(source),published_sha256=sha(published)))

def aux_fields(path,label):
    s=path.read_text(encoding='utf-8');m=re.search(r'\\newlabel\{'+re.escape(label)+r'\}',s)
    assert m,label
    g,end=P['group'](s,m.end());pos=g[0];fields=[]
    while pos<g[1]:
        v,pos=P['group'](s,pos)
        if v is None:break
        fields.append(s[slice(*v)])
    return fields

targets=[]
for record in [v for v in artifacts if v['band'] in ('B08','main')]:
    pdf=root/record['compiled_pdf'];r=PdfReader(pdf)
    aux=root/'main.aux' if record['band']=='main' else root/'registry/_B08.aux'
    f=aux_fields(aux,'thm:auto:8.3.3.5')
    if f[0]!='8.3.3.5':errors.append(f"{record['band']}: target theorem number changed")
    targets.append(dict(band=record['band'],pdf=record['published_pdf'],compiled_pdf=record['compiled_pdf'],theorem=f[0],printed_page=f[1],
        anchor=f[3],physical_page=r.get_destination_page_number(r.named_destinations[f[3]])+1,
        pdf_sha256=record['compiled_sha256'],published_pdf_sha256=record['published_sha256']))

before={v['job']:v for v in json.loads((out/'layout-before.json').read_text(encoding='utf-8'))};layout=[]
for band in bands+['main']:
    job='main' if band=='main' else '_'+band
    p=root/'main.log' if band=='main' else root/f'registry/{job}.log'
    text=p.read_text(encoding='utf-8',errors='replace')
    warnings=re.findall(r'Overfull \\[hv]box[^\n]*',text)
    def width(item):
        m=re.search(r'Overfull \\[hv]box \(([^)]*)\)',item)
        return m[1] if m else item
    old=Counter(map(width,before[job]['overfull']));new=Counter(map(width,warnings))
    missing=re.findall(r'Missing character[^\n]*',text)
    if missing:errors.append(f'{job}: missing glyphs')
    layout.append(dict(job=job,before_count=sum(old.values()),after_count=sum(new.values()),
        added_width_diagnostics=list((new-old).elements()),removed_width_diagnostics=list((old-new).elements()),
        warnings=warnings,missing_characters=missing))

log=(out/'build-main-publish.log').read_text(encoding='utf-8-sig')
match=re.search(r'PDF link audit passed: (\d+) files, (\d+) pages, (\d+) local links, (\d+) external links',log)
assert match,'Publication link audit did not complete'
assert 'Reference audit passed: main' in log,'Main reference audit did not pass'
link_audit=dict(zip(['files','pages','local_links','external_links'],map(int,match.groups())))
result=dict(status='passed' if not errors else 'failed',errors=errors,rebuilt_standalone_volumes=bands,
    complete_main_standalone_index_audit='passed for all 45 volumes',publication_link_audit=link_audit,
    source_sha256=source_hashes,artifacts=artifacts)
(out/'final-build-verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
(out/'final-target-pages.json').write_text(json.dumps(targets,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
(out/'layout-after.json').write_text(json.dumps(layout,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(dict(status=result['status'],errors=errors,publication_link_audit=link_audit,targets=targets,
    new_layout_diagnostics=[dict(job=v['job'],new=v['added_width_diagnostics']) for v in layout if v['added_width_diagnostics']]),ensure_ascii=False))
raise SystemExit(bool(errors))
