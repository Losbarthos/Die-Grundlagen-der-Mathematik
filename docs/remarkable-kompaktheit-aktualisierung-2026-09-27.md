# reMarkable-Aktualisierung: Totale Beschränktheit und Kompaktheit

Am 27. September 2026 wurden die PDF-Dokumente unter
`Meine Dateien/Mathematik/Grundlagen der Mathematik` mit dem aktuellen
Projektordner `output/` abgeglichen. Die Abschlussprüfung um 19:11 Uhr
(Europe/Berlin) bestätigt **72 von 72 aktiven PDFs** als bytegenau identisch
mit den Projektdateien, jeweils im richtigen Ordner. Verglichen wurden die
SHA-256-Prüfsummen der vollständigen PDF-Dateien.

## Aktualisierte und ergänzte Dokumente

Die aktuellen Fassungen von B00, Gesamtband und B47 wurden in ihre bisherigen
aktiven Ordner importiert. Die beiden neuen Begleitfassungen liegen unter
`10 Metrische Räume/Ergänzungen/Totale Beschränktheit und Kompaktheit`.

| Dokument | Neue aktive Dokument-ID |
|---|---|
| Bd. 00 - Überblick über die Bände | `08bb56c8-7d9d-4225-99dc-cebc0dbff563` |
| Die Grundlagen der Mathematik - Gesamtband | `c5b94111-0b99-4295-b455-6e1ea982e16c` |
| Bd. 47 - Metrische Räume und Vollständigkeit | `eaa3b887-ab73-4c90-a128-239f886df6dd` |
| Bd. 47 - Totale Beschränktheit und Kompaktheit - Beweise | `70a1039e-4216-4e46-ab59-a5b96572078f` |
| Bd. 47 - Totale Beschränktheit und Kompaktheit - Lesefassung | `7e0eb7bc-18cd-4f4d-bceb-fbfaff0bf51b` |

Der neue Kompaktheitsordner hat die ID
`05d5f357-1a18-4312-a65d-83eb9bc3b4ac`; sein übergeordneter Ordner
`Ergänzungen` die ID `43d43279-9934-44c8-b4b6-b795e7ea432d`.

## Erhaltene Vorgänger und Anmerkungen

Die drei vorherigen Fassungen wurden mit ihren bisherigen Dokument-IDs in
neue Unterordner `Archiv 2026-09-27 - Kompaktheit` verschoben. Ihre PDF-Dateien
blieben bytegenau unverändert. Bei diesen drei Dokumenten lagen im
Ausgangsbestand keine lokalen Anmerkungsdateien vor.

| Vorgänger | Erhaltene Dokument-ID | Archiv |
|---|---|---|
| B00 | `f4be7548-59a9-4ba8-bfe2-407b420efb16` | `00 Einstieg und Gesamtband/Archiv 2026-09-27 - Kompaktheit` |
| Gesamtband | `38234794-dcf1-423d-89bd-351baccf5f6f` | `00 Einstieg und Gesamtband/Archiv 2026-09-27 - Kompaktheit` |
| B47 | `ff9b7b70-676a-41ec-8c1f-a08cdd2486a8` | `10 Metrische Räume/Archiv 2026-09-27 - Kompaktheit` |

Die beiden neuen Archivordner haben die IDs
`caf68e2c-bb5b-482d-ab1b-14bf501817e9` (00) und
`c5405e91-99ba-4bbe-b00e-de549557e9e4` (10).

Die Prüfung gegen den zuvor gespeicherten Bestand bestätigt außerdem:

- Alle **67 bereits aktuellen aktiven Dokumente** behalten ihre IDs,
  Ordnerzuordnungen und unveränderten PDF-Dateien.
- Alle **37 zuvor vorhandenen Archivdokumente** behalten ihre IDs,
  Ordnerzuordnungen und unveränderten PDF-Dateien.
- Sämtliche **21 zuvor vorhandenen Anmerkungsdateien** sind bytegenau
  unverändert: acht an der archivierten Nullprodukt-Lesefassung und
  fünf beziehungsweise acht an zwei archivierten Gruppenrekonstruktions-Lesefassungen.
- Alle zuvor vorhandenen Ordner-IDs sind erhalten. Der Zielbestand umfasst
  jetzt **72 aktive und 40 archivierte Dokumente**.
- Es gibt keine fehlenden oder abweichenden PDFs, aktiven Duplikate,
  zusätzlichen aktiven Dokumente oder falsch einsortierten aktuellen Fassungen.
- Die 72 Projekt-PDFs in `output/` blieben während des Abgleichs unverändert.

## Prüfnachweise

- [Ausgangsvergleich](../tmp/remarkable-sync/comparison-kompaktheit-vorher.json)
- [Ausgangsvergleich als Übersicht](../tmp/remarkable-sync/comparison-kompaktheit-vorher.md)
- [Snapshot mit Original-IDs, Ordner-IDs, PDF- und Anmerkungshashes](../tmp/remarkable-sync/kompaktheit-erhaltung-vorher.json)
- [Teilprüfung nach B00 und Gesamtband](../tmp/remarkable-sync/comparison-kompaktheit-nach-00.json)
- [Abschlussvergleich aller 72 PDFs](../tmp/remarkable-sync/comparison-kompaktheit-nachher.json)
- [Lesbare Abschlussübersicht](../tmp/remarkable-sync/comparison-kompaktheit-nachher.md)
- [Erhaltungsprüfung gegen den Ausgangsbestand](../tmp/remarkable-sync/kompaktheit-nachher-erhaltung.json)

Geprüft wurde ausschließlich lesend der lokale Dokumentbestand der
reMarkable-Desktop-App unter
`C:/Users/Martin Kunze/AppData/Roaming/remarkable/desktop`. Import,
Ordneranlage und Archivierung erfolgten über die App-Oberfläche.
Die Prüfung bestätigt die aktualisierte Desktop-App. Der tatsächliche
Synchronisationsstand des physischen reMarkable-Tablets wurde nicht
unabhängig geprüft. Frühere Berichte und Nachweise bleiben erhalten.

Zusätzlich wurde nach allen Importen in der App-Oberfläche unter
`Einstellungen > Cloud > Verbindungscheck` ausdrücklich ein Verbindungscheck
ausgeführt. Nach `Checking internet connection...` meldete die App:
`No syncing errors found. If you still experience problems, try restarting your device.`
Der Cloud-Verbindungscheck meldet damit keine Synchronisierungsfehler;
die Ankunft auf dem physischen Tablet bleibt unabhängig davon ungeprüft.
