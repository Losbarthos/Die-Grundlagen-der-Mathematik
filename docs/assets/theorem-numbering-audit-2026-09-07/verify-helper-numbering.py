"""Check registered helper displays and anchors in the 45 standalone AUX files."""
from collections import defaultdict
from pathlib import Path
import json
import re
import runpy

ARCHIVE = Path(__file__).resolve().parent
ROOT = next(
    parent for parent in ARCHIVE.parents
    if (parent / 'scripts/proof-source-audit.py').is_file()
    and (parent / 'tex/impl/proof-tables.tex').is_file()
)
GROUP = runpy.run_path(str(ROOT / 'scripts/proof-source-audit.py'))['group']
LABEL = re.compile(r'\\newlabel\{(thm:pp:(.+?):(\d+))\}')

inventory = []
errors = []
occurrences = defaultdict(list)
for band in range(45):
    relative = f'registry/_B{band:02d}.aux'
    path = ROOT / relative
    count = 0
    if not path.is_file():
        errors.append({'file': relative, 'issue': 'missing_aux'})
    else:
        source = path.read_text(encoding='utf-8')
        for match in LABEL.finditer(source):
            label, parent, index = match.groups()
            count += 1
            location = {'file': relative, 'line': source.count('\n', 0, match.start()) + 1}
            occurrences[label].append(location)
            try:
                payload, _ = GROUP(source, match.end())
                if payload is None:
                    raise ValueError('Missing label payload')
                fields = []
                position = payload[0]
                while position < payload[1]:
                    field, position = GROUP(source, position)
                    if field is None or position > payload[1]:
                        raise ValueError('Malformed label payload')
                    fields.append(source[slice(*field)])
                if len(fields) < 4:
                    raise ValueError('Missing display or anchor field')
            except ValueError as exc:
                errors.append({**location, 'label': label, 'issue': 'malformed_label', 'detail': str(exc)})
                continue
            for issue, actual, expected in (
                ('display', fields[0], f'{parent}(H{index})'),
                ('anchor', fields[3], f'proofpartnr.{parent}.{index}'),
            ):
                if actual != expected:
                    errors.append({**location, 'label': label, 'issue': issue,
                                   'actual': actual, 'expected': expected})
    inventory.append({'band': f'B{band:02d}', 'registered_helpers': count})

duplicates = [
    {'label': label, 'occurrences': locations}
    for label, locations in occurrences.items() if len(locations) > 1
]
errors.extend({'issue': 'duplicate_label', **entry} for entry in duplicates)
result = {
    'volumes': len(inventory),
    'helpers': sum(row['registered_helpers'] for row in inventory),
    'unique_helper_labels': len(occurrences),
    'duplicate_labels': duplicates,
    'errors': errors,
    'inventory': inventory,
}
(ARCHIVE / 'final-helper-verification.json').write_text(
    json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
)
print(f"Volumes: {result['volumes']}; registered helpers: {result['helpers']}; "
      f"duplicate labels: {len(duplicates)}; errors: {len(errors)}")
if errors:
    print(json.dumps(errors[:10], ensure_ascii=False, indent=2))
    raise SystemExit(1)
