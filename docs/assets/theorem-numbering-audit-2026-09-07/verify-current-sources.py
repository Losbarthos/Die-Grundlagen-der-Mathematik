"""Recheck the 58 recorded theorem displays; not a proof verifier."""
from pathlib import Path
import hashlib
import json
import re
import runpy

archive = Path(__file__).resolve().parent
root = archive.parents[2]
parser = runpy.run_path(str(root / 'scripts/proof-source-audit.py'))
checks = []
errors = []
cache = {}
seen = set()
roman = ['i', 'ii', 'iii', 'iv', 'v', 'vi', 'vii', 'viii']
for name in ['b01-b14-b19-changes.json', 'b15-b27-changes.json', 'b28-changes.json']:
    for row in json.loads((archive / name).read_text(encoding='utf-8')):
        key = row.get('id', row.get('key'))
        if key in seen:
            errors.append(f'Duplicate recorded ID: {key}')
        seen.add(key)
        path = root / row['file']
        if path not in cache:
            text = path.read_text(encoding='utf-8-sig')
            masked = parser['mask_comments'](text)
            calls = {}
            for match in re.finditer(r'\\FormulaThmDeltaKR\b', masked):
                call = parser['call'](masked, match.start(), 4)
                identity = text[slice(*call.args[2])]
                if identity in calls:
                    errors.append(f'Duplicate current KR ID: {identity}')
                calls[identity] = call
            cache[path] = (text, calls)
        text, calls = cache[path]
        if key not in calls:
            errors.append(f'KR declaration missing: {key}')
            continue
        call = calls[key]
        display = text[slice(*call.args[0])]
        original = text[slice(*call.args[1])]
        tags = re.findall(r'\\text\{\(([ivx]+)\)\}', display)
        band = '28' if row['file'].startswith('tex') else row['file'][4:6]
        registry = (root / f'registry/_B{band}.registry.tsv').read_text(encoding='utf-8')
        number_match = re.search(r'^ID\t' + re.escape(key) + r'\ttheorem\tthm:auto:([^\r\n]+)', registry, re.M)
        number = number_match[1] if number_match else None
        result = {
            'key': key, 'file': row['file'], 'line': text.count('\n', 0, call.start) + 1,
            'count': len(tags), 'tags': tags,
            'display_equals_archived_current_display': display == row['current_display'],
            'original_structure_exact': original == row['original_structural_key'],
            'consecutive_tags_and_count_exact': tags == roman[:row['count']],
            'source_snapshot_hash_matches': hashlib.sha256(path.read_bytes()).hexdigest() == row['current_source_sha256'],
            'source_line_matches': text.count('\n', 0, call.start) + 1 == row['current_source_line'],
            'registry_number': number,
            'registry_number_matches': number == row['current_theorem_number'],
            'no_glued_vdash_token': not bool(re.search(r'\\vdash[A-Za-z]', display)),
        }
        for field in ['display_equals_archived_current_display', 'original_structure_exact',
                      'consecutive_tags_and_count_exact', 'source_snapshot_hash_matches', 'source_line_matches',
                      'registry_number_matches', 'no_glued_vdash_token']:
            if not result[field]:
                errors.append(f'{key}: {field}')
        checks.append(result)

unrecorded = sorted({key for text, calls in cache.values() for key in calls} - seen)
if unrecorded:
    errors.append(f'Unrecorded KR IDs in changed files: {unrecorded}')
b00_files = [root / 'Bd. 00 - Überblick über die Bände.tex', *(root / 'tex/ueberblick').glob('*.tex')]
b00_theorems = []
for path in b00_files:
    text = parser['mask_comments'](path.read_text(encoding='utf-8-sig'))
    if re.search(r'\\FormulaThm[A-Za-z]*|\\begin\{(?:theorem|formulaThm|lemma|satz|proposition|corollary)\}', text):
        b00_theorems.append(str(path.relative_to(root)))
if b00_theorems:
    errors.append(f'Unexpected B00 theorem declarations: {b00_theorems}')
if len(checks) != 58 or sum(item['count'] for item in checks) != 192:
    errors.append('Recorded totals differ from 58 families / 192 conclusions')
output = {
    'scope': 'Recorded numbering changes and B00 theorem absence; no mathematical proof verification.',
    'families': len(checks), 'conclusions': sum(item['count'] for item in checks),
    'b00_files_checked': len(b00_files), 'b00_theorems_found': b00_theorems,
    'source_sha256': {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in cache},
    'errors': errors, 'checks': checks,
}
(archive / 'global-current-source-checks.json').write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps({'families': output['families'], 'conclusions': output['conclusions'], 'errors': errors}, ensure_ascii=False))
raise SystemExit(bool(errors))
