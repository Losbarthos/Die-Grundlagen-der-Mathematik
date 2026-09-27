# reMarkable-Abgleich vom 26. September 2026

Der lokale Dokumentbestand der reMarkable-Desktop-App unter
`Meine Dateien/Mathematik/Grundlagen der Mathematik` wurde mit dem Projektordner
`output/` abgeglichen. Maßgeblich waren die vollständigen SHA-256-Prüfsummen
der PDF-Dateien und ihre jeweiligen Ordnerpfade.

## Ergebnis

- Alle **70 aktuellen PDFs** sind im passenden aktiven App-Ordner vorhanden
  und bytegenau identisch mit `output/`.
- **13 veraltete PDFs** wurden durch aktuelle Fassungen ersetzt. Ihre bisherigen
  Dokument-IDs und unveränderten PDF-Dateien bleiben in den vorhandenen
  Unterordnern `Archiv vor Aktualisierung 2026-09-25` erhalten.
- Die **zwei neuen Nullprodukt-Ausgaben** wurden unter
  `07 Halbgruppen und Monoide/Ergänzungen/Nullprodukt-Rekonstruktion/` ergänzt.
- Die **55 bereits aktuellen Dokumente** behalten ihre bisherigen IDs und
  unveränderten PDF-Dateien. Es gibt keine fehlenden PDFs, aktiven Duplikate,
  zusätzlichen aktiven Dokumente oder falsch einsortierten Fassungen.
- Die archivierte Gruppenrekonstruktions-Lesefassung behält ihre **acht
  Anmerkungsdateien**; deren SHA-256-Prüfsummen sind sämtlich unverändert.
- Auch die **23 schon zuvor archivierten Dokumente** sind mit ihren IDs und
  PDF-Prüfsummen erhalten. Insgesamt umfasst der Zielbestand jetzt 70 aktive
  und 36 archivierte Dokumente. `output/` blieb während des Abgleichs unverändert.

Aktualisiert wurden B00, Gesamtband, B03, B05, B08, B09, B12, B20, B28, B33,
B37 sowie beide Begleitfassungen zur Gruppenrekonstruktion.

## Prüfnachweise

- Ausgangsbestand und Zuordnung:
  [`tmp/remarkable-sync/comparison-before.json`](../tmp/remarkable-sync/comparison-before.json)
- Abschlussvergleich aller PDFs, Dokument-IDs und Ordnerpfade:
  [`tmp/remarkable-sync/comparison-after.json`](../tmp/remarkable-sync/comparison-after.json)
- Lesbare Übersicht:
  [`tmp/remarkable-sync/comparison-after.md`](../tmp/remarkable-sync/comparison-after.md)
- Prüfung der erhaltenen Vorgänger, unveränderten Dokumente und Anmerkungen:
  [`tmp/remarkable-sync/preservation-after.json`](../tmp/remarkable-sync/preservation-after.json)
- Ausgangshashes der acht Anmerkungsdateien:
  [`tmp/remarkable-sync/gruppenrekonstruktion-annotations-before.json`](../tmp/remarkable-sync/gruppenrekonstruktion-annotations-before.json)

Die Abschlussprüfung liest den lokalen App-Dokumentbestand unter
`C:/Users/Martin Kunze/AppData/Roaming/remarkable/desktop`.
Sie bestätigt die erfolgreiche Aktualisierung der Desktop-App. Der tatsächliche
Synchronisationsstand des reMarkable-Tablets wurde nicht unabhängig geprüft.
