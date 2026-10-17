"""Compare historical edition identities without discarding current metadata."""
from collections import Counter


def registry_records(rows, *, legacy_manifest=False):
    """Return comparable records; only manifests omit appended display columns.

    Structural rows historically had seven columns (the last, title, could be
    omitted when empty); ID rows had four. Current-to-current comparisons retain
    every column so stale or truncated proof-reference imports still fail.
    """
    records = []
    for row in rows:
        row = list(row)
        if len(row) < 4:
            raise ValueError(f"Malformed theorem registry row: {row!r}")
        kind = "ID" if row[0] == "ID" else "statement"
        if legacy_manifest:
            width = 4 if kind == "ID" else 7
            row = (row + [""] * width)[:width]
        # Structural version/insertion fields are not part of result identity.
        records.append((kind, *row[1:]))
    return Counter(records)
