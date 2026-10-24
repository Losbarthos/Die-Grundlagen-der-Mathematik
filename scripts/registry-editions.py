"""Compare historical edition identities without discarding current metadata."""
from collections import Counter
import re


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


def validate_private_registry(rows, aux, private_ids, prefix):
    """Validate unique semantic IDs and consistent formula/name aliases."""
    identities = [row for row in rows if row[0] == "ID"]
    if Counter(row[1] for row in identities) != Counter(private_ids):
        raise ValueError("Private registry: duplicate, missing or unexpected semantic IDs")
    identifiers = {row[1]: row[3] for row in identities}
    labels = set(identifiers.values())
    if len(labels) != len(identifiers):
        raise ValueError("Private registry: two semantic IDs share one local declaration")
    row_label = lambda row: row[3] if row[0] == "ID" else row[1]
    if set(map(row_label, rows)) != labels:
        raise ValueError("Private registry: statement without a permitted semantic ID")
    for key, label in identifiers.items():
        if not re.fullmatch(r"(?:thm|def):auto:" + re.escape(prefix) + r"(?:\.\d+)+", label):
            raise ValueError(f"Private label is outside {prefix}: {key}")
        number, destination = aux.get(label, ("", ""))
        if not number.startswith(prefix + ".") or not destination:
            raise ValueError(f"Private result has no {prefix} number/destination: {key}")
        local = [row for row in rows if row_label(row) == label]
        identity = next(row for row in local if row[0] == "ID")
        legacy = [row for row in local if row[0] != "ID"]
        if not legacy or len(identity) < 7 or any(len(row) < 9 for row in legacy):
            raise ValueError(f"Incomplete private declaration metadata: {key}")
        for column in (4, 5):
            if len({row[column] for row in legacy}) != len(legacy):
                raise ValueError(f"Duplicate private formula lookup or alias: {key}")
        kind = "definition" if label.startswith("def:") else "theorem"
        if identity[2] != kind:
            raise ValueError(f"Private identity kind differs from its label: {key}")
        metadata = legacy[0][6:]
        for row in legacy:
            if row[2] != kind or row[6:] != metadata or row[7:9] != identity[5:7]:
                raise ValueError(f"Inconsistent private formula alias metadata: {key}")
        for row in local:
            if (row[4] if row[0] == "ID" else row[3]) != number:
                raise ValueError(f"Private registry/AUX number mismatch: {key}")
    return identifiers
