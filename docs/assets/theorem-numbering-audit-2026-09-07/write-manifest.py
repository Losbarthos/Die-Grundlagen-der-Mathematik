"""Refresh checksums after adding final build or visual-review records."""
from pathlib import Path
import hashlib
import json

archive = Path(__file__).resolve().parent
entries = [
    {'file': str(path.relative_to(archive)).replace('\\', '/'),
     'bytes': path.stat().st_size,
     'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    for path in sorted(archive.rglob('*'))
    if path.is_file() and path.name != 'manifest-sha256.json'
]
(archive / 'manifest-sha256.json').write_text(json.dumps(entries, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'{len(entries)} Dateien im SHA256-Manifest.')
