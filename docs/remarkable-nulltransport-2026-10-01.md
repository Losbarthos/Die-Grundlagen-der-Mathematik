# reMarkable-Aktualisierung zum Nullelement-Transport, 01.10.2026

## Phase 1: Fachbände und Ergänzungen

Die Aktualisierung erfolgte über die Oberfläche der reMarkable-Desktop-App im vorhandenen Zielordner `Meine Dateien/Mathematik/Grundlagen der Mathematik`. Es wurden keine App-Daten direkt geschrieben und keine Dokumente gelöscht.

Die bisherigen Bände 28 und 33 wurden vollständig in `07 Halbgruppen und Monoide/Archiv 2026-10-01 - Nulltransport` verschoben. Die bisherigen beiden Nullprodukt-Fassungen wurden in den gleichnamigen Datumsordner innerhalb von `Ergänzungen/Nullprodukt-Rekonstruktion` verschoben. Ihre Dokumentidentitäten blieben erhalten.

An den aktiven Ursprungsorten wurden die veröffentlichten Ersatz-PDFs importiert:

- Band 28 – Halbgruppen: 228 Seiten;
- Band 33 – Halbgruppen mit Nullelement: 44 Seiten;
- Band 37 – Nullprodukt-Rekonstruktion, Lesefassung: 37 Seiten;
- Band 37 – Nullprodukt-Rekonstruktion, Beweistabellen: 35 Seiten.

Unter `Ergänzungen/Nullelement-Transport` wurden die neue Lesefassung mit 5 Seiten und die neuen Beweistabellen mit 16 Seiten hinzugefügt. Die App übernahm die Dateien einzeln; ein erster Versuch mit zwei Dateipfaden importierte nur die erste Datei. Vor dem ergänzenden Einzelimport wurde dieser Zustand lesend geprüft, sodass keine Dublette entstand.

Der anschließende vollständige Vergleich bestätigte **74 aktive PDFs, alle 74 SHA-256-identisch mit `output/`**, sowie 44 archivierte Dokumente und keine zusätzlichen aktiven Dokumente. Alle 68 unveränderten aktiven Originale einschließlich des Gesamtbands und alle 40 früheren Archivdokumente behielten Identität, Ablageort, PDF-Prüfsumme sowie vorhandenen Anmerkungsbestand. Die vier neu archivierten Original-PDFs sind unverändert erhalten. Insbesondere sind alle **13 `.rm`-Dateien** der alten Nullprodukt-Lesefassung anhand ihrer individuellen SHA-256-Prüfsummen unverändert bestätigt.

Nachweise:

- `tmp/remarkable-sync/comparison-anmerkungen-2026-10-01-vorher.json`;
- `tmp/remarkable-sync/anmerkungen-2026-10-01-alle-fuenf-originale-vorher.json`;
- `tmp/remarkable-sync/comparison-anmerkungen-2026-10-01-phase1-nachher.json`;
- `tmp/remarkable-sync/anmerkungen-2026-10-01-phase1-preservation.json`.

Der Gesamtband wurde in dieser Phase ausdrücklich noch nicht archiviert oder ersetzt.

## Phase 2: Gesamtband und abschließender Bestand

Nach gesonderter Freigabe wurde der bisherige Gesamtband über die App-Oberfläche in `00 Einstieg und Gesamtband/Archiv 2026-10-01 - Nulltransport` verschoben. Seine bisherige Dokumentidentität und PDF-Prüfsumme blieben erhalten. Anschließend wurde die veröffentlichte Gesamtband-PDF am aktiven Ursprungsort importiert. Die geöffnete Ausgabe zeigte in der App **2742 Seiten**.

Der finale Vergleich bestätigte:

- **74 aktive PDFs**, jeweils genau einmal am vorgesehenen Zielpfad und SHA-256-identisch mit `output/`;
- **67 unveränderte aktive Originale** mit unveränderten IDs, Ablageorten, PDF-Prüfsummen und Anmerkungsbeständen;
- **40 frühere Archivdokumente**, ebenfalls unverändert;
- **5 neu archivierte Originale** mit unveränderten PDF-Prüfsummen und Dokumentidentitäten;
- weiterhin **13 unveränderte `.rm`-Anmerkungsdateien** der alten Nullprodukt-Lesefassung, einzeln per SHA-256 bestätigt;
- insgesamt **45 archivierte Dokumente**, keine zusätzlichen aktiven Dokumente und keine Dubletten.

Finale Nachweise:

- `tmp/remarkable-sync/comparison-anmerkungen-2026-10-01-phase2-nachher.json`;
- `tmp/remarkable-sync/anmerkungen-2026-10-01-phase2-preservation.json`;
- Prüfskript `tmp/remarkable-sync/check-preservation-2026-10-01.py --final`.

Die Feststellungen betreffen den lokalen Bestand der Desktop-App; ein unabhängiger Nachweis auf dem physischen Tablet ist damit nicht verbunden.
