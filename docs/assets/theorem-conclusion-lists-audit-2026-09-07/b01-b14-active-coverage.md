# B01–B14: aktive Deckung des Schlusslisten-Inventars

Die zuerst gemeldeten 1.436 Hauptdeklarationen waren ein Quellen-Rohbestand einschließlich deaktivierter Textblöcke. Die belastbare aktive Zählung lautet **1.350 Haupttheoreme**; die ausgeschlossenen Deklarationen stehen ausschließlich in drei expliziten `\iffalse`-Blöcken von Band 10. Registrierte Hilfssätze sind entsprechend getrennt ausgewiesen.

| Band | Haupt aktiv | Hilfssätze aktiv | Haupt deaktiviert | Hilfssätze deaktiviert | Aktive breite Anzeigen gelesen | Aktive bestehende Familien |
|---|---:|---:|---:|---:|---:|---:|
| 01 | 0 | 0 | 0 | 0 | 0 | 0 |
| 02 | 271 | 0 | 0 | 0 | 6 | 0 |
| 03 | 308 | 20 | 0 | 0 | 56 | 2 |
| 04 | 10 | 0 | 0 | 0 | 5 | 0 |
| 05 | 123 | 32 | 0 | 0 | 27 | 1 |
| 06 | 36 | 10 | 0 | 0 | 10 | 0 |
| 07 | 55 | 4 | 0 | 0 | 14 | 0 |
| 08 | 94 | 41 | 0 | 0 | 43 | 4 |
| 09 | 23 | 2 | 0 | 0 | 10 | 0 |
| 10 | 319 | 110 | 86 | 31 | 73 | 1 |
| 11 | 56 | 47 | 0 | 0 | 16 | 0 |
| 12 | 10 | 3 | 0 | 0 | 6 | 0 |
| 13 | 28 | 4 | 0 | 0 | 30 | 0 |
| 14 | 17 | 0 | 0 | 0 | 17 | 0 |

Aktive Summe: 1350 Haupttheoreme + 273 Hilfssätze = 1623 Anzeigen. Deaktiviert: 86 Haupt- und 31 Hilfsdeklarationen. Von den ursprünglich 338 gelesenen breiten Kandidaten sind 313 aktiv; alle acht bestehenden nummerierten Familien sind aktiv. Keine zusätzliche Schlussliste gefunden.

Die aktive Reihenfolge der Hauptdeklarationen wurde gegen sämtliche einzigartigen `thm:auto:`-Labels des jeweiligen Bandregisters abgeglichen. Die registrierten Hilfs-IDs und ihre zugeordneten Hauptsätze/Teilnummern wurden ebenfalls mit `thm:pp:` verglichen. Die resultierenden Labelmengen sind in allen 14 Bänden exakt gleich den Registern; keine bloße Summenübereinstimmung und keine ungeklärte Zähldifferenz.

Deaktivierte Quellbereiche:

- `Bd. 10 - Natürliche Zahlen.tex`, Zeilen 1105–1322.
- `Bd. 10 - Natürliche Zahlen.tex`, Zeilen 1527–4371.
- `Bd. 10 - Natürliche Zahlen.tex`, Zeilen 5997–6426.

Das vollständige Inventar behält die Rohdeklarationen mit einem expliziten `active`-Feld und führt `active_declarations` und `inactive_excluded` getrennt. `b01-b14-active-coverage.json` enthält Zählungen und Deckungsresultate. Der ursprüngliche negative Befund zu unabhängigen Schlusslisten bleibt unverändert. Keine Quelle verändert, keine PDFs erzeugt und kein Build ausgeführt.
