# Gesicherte Belege zur Teilnummerierung

Diese Belege gehören zum [Bericht zur Theoremnummerierung](../../theorem-numbering-audit-2026-09-07.md) vom 7. September 2026. Die Quellenprüfung erfasst Band 00 bis 44 einschließlich der aktiven B28-Isomorphiesammlung. Die Änderung betrifft 58 Familien mit 192 sichtbaren Aussagekennzeichnungen.

## Änderungsinventar und aktuelle Anzeigen

- [Band 01–14 und 19](b01-b14-b19-changes.json): 9 Familien, 34 Aussagen.
- [Band 15–27 ohne 19](b15-b27-changes.json): 20 Familien, 50 Aussagen.
- [Band 28 einschließlich Beispielen](b28-changes.json): 29 Familien, 108 Aussagen.

Die drei Inventare enthalten jeweils das exakte unveränderte `original_structural_key`-Argument und die aktuelle sichtbare `current_display`-Anzeige, die stabile ID, die tatsächliche Theoremnummer aus der Registry und die gezählten römischen Kennzeichnungen. Historische Felder wie `display`, `conclusions`, `line` oder `line_before` bleiben als Dokumentation der ersten Bearbeitung erhalten; für den Schlussstand ist ausdrücklich `current_display` maßgeblich. In Band 28 enthält dieses Feld auch die später präzisierten Konjunktionen der Neutral-/Nullbedingungen und die explizit quantifizierte Voraussetzung für den Einheitentransport. Die ursprüngliche Strukturformel wurde dabei nicht geändert.

## Umfang der Kandidatenprüfung

Die vier Gruppenberichte [01–14/19](b01-b14-b19-report.md), [15–27](b15-b27-report.md), [28](b28-independent-family-review.md) und [29–44](b29-b44-report.md) dokumentieren die Abgrenzung unabhängiger Schlussaussagen von einzelnen Konjunktionen, Gleichheitsketten, Prämissenlisten und gebundenen Variablenlisten. Die zugehörigen Kandidaten-, Zähl- und Prüfdateien liegen ebenfalls in diesem Verzeichnis. Band 29–44 benötigte keine zusätzliche Familiennummerierung. Der B28-Bericht und die aktuelle globale Prüfung enthalten auch die Negativprüfung von Band 00 samt seinen eingebundenen Übersichtsdateien.

Ältere Berichte verweisen teilweise auf Arbeitspfade, Ausgangskopien oder Zwischenbilder unter `tmp/`. Diese historischen Arbeitsprodukte werden hier nicht vorausgesetzt: Die geprüften Kandidaten, Formelausschnitte, Original-Strukturargumente und aktuellen Anzeigen sind dauerhaft gesichert. Große vollständige Quellenkopien, PDF-Dateien und Seitenbilder wurden absichtlich nicht übernommen. Historische Zeilen-/Seitenangaben können durch spätere lokale Umbruchkorrekturen überholt sein; stabile IDs bleiben maßgeblich.

## Wiederholbare Quellenprüfung

[verify-current-sources.py](verify-current-sources.py) prüft alle 58 Datensätze gegen die aktuellen KR-Deklarationen im Repository, die exakten Original-Strukturargumente, fortlaufende römische Kennzeichnungen und aktuelle Registrynummern. Das Skript nutzt den versionierten klammerbalancierenden Parser `scripts/proof-source-audit.py` und benötigt keine Dateien aus `tmp/`. [global-current-source-checks.json](global-current-source-checks.json) enthält das konkrete Prüfergebnis und Quellenprüfsummen.

Die [abschließenden Build- und Linkprüfungen](final-build-verification.json) sind bestanden: 45 Einzelbände, ein Gesamtband und 46 veröffentlichte PDFs. Die fünf gesicherten Buildprotokolle dokumentieren den vollständigen Durchlauf einschließlich der behobenen B37-Unterbrechung. Die [koordinierende Sichtprüfung](root-pdf-qa.md), [B21/B26-Prüfung](b21-b26-pdf-qa-report.md), [B28-Beispielprüfung](b28-examples-final-qa.md) und [B28-Mogiljanskaja-Prüfung](b28-mog-pdf-qa-report.md) erfassen zusammen alle 58 geänderten Familien. Spätere lokale B28-Textumbrüche änderten die Mogiljanskaja-Anzeigen selbst nicht; die aktualisierte Seitenzuordnung steht in `b28-final-pages.json`. Dieser Belegstand behauptet weder eine mathematische Verifikation noch eine vollständige Formalisierung aller Beweise. Die noch offenen fachlichen Beweislücken stehen im [Beweisregelbericht](../../proof-rules-audit-2026-09-07.md).

Ein unabhängig geschriebener [zweiter Prüfer](independent-ledger-check.py) bestätigt dieselben 58 Familien und 192 Tags einschließlich sämtlicher Quellzeilen und Dateihashes. Sein [Bericht](independent-ledger-check.md) und [Einzelergebnis](independent-ledger-check.json) sind ebenfalls gesichert. Er wird vom Repository-Stamm aus aufgerufen; für diese dauerhafte Kopie wurde ausschließlich der JSON-Ausgabepfad vom Arbeitsordner auf dieses Archiv umgestellt.

[verify-helper-numbering.py](verify-helper-numbering.py) prüft in allen 45 fertigen Standalone-AUX-Dateien die registrierten Hilfssatzlabels: Anzeige `<parent>(H<index>)`, unveränderter Anker `proofpartnr.<parent>.<index>` sowie doppelte Labels innerhalb und zwischen den Dateien. Der Prüfer ermittelt den Repository-Stamm aus seinem eigenen Dateipfad und kann daher aus jedem Arbeitsverzeichnis aufgerufen werden. Er schreibt [final-helper-verification.json](final-helper-verification.json) direkt in dieses Archiv; der geprüfte Schlussstand enthält 929 registrierte Hilfssätze ohne Fehler oder doppelte Labels.

[manifest-sha256.json](manifest-sha256.json) verzeichnet Größe und SHA256 jeder gesicherten Datei außer dem Manifest selbst. Nach einer Ergänzung der finalen Prüfbelege kann [write-manifest.py](write-manifest.py) das Manifest neu erzeugen.
