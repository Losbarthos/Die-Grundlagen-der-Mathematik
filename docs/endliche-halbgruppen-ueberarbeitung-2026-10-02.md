# Band 37: Überarbeitung und Lesefassung

Stand: 2. Oktober 2026.

Die bisher rein im Fließtext geführten Beweise sind durch Tabellenableitungen
ergänzt oder ersetzt: 15 im Strukturkapitel, sieben im Tafelkapitel und
zwei bei der Rekonstruktion. Die ausführlichen Struktur- und Tafelbeweise
liegen in kleinen Quelldateien unter `tex/b37/structure/` und
`tex/b37/tables/`; sie werden an den bisherigen Satzstellen eingebunden.
Sieben registrierte H-Hilfsaussagen erklären den Strukturtransport und den
kanonischen Tafelcode. Die bisherigen öffentlichen Aussagen, Nummern und
PDF-Zielmarken bleiben erhalten. Der unveränderte Nullprodukt-Baseline-Manifest
wird weiterhin geprüft; die sieben neuen H-IDs sind ausdrücklich zugelassen.

Neue Absatzüberschriften trennen Existenz, Eindeutigkeit, Potenzreduktion,
Idempotenz und Minimalideal. Das Tafelbeispiel unterscheidet jetzt
Grundtafel, Teilrechteckrechnung und die vollständige Potenztafel. Die
Absatzüberschriften vermeiden zusätzliche Hyperref-Abschnittszähler, damit
frühere Ergebnislinks gültig bleiben. Zwei verkürzte DOI-Adressen wurden an
die vollständigen Adressen im selben Kapitel angepasst.

Die neue Lesefassung **Endliche Halbgruppen erkennen** entwickelt den
Zusammenhang an einer monogenen Dreierhalbgruppe mit Index 2 und Periode 2.
Sie führt über Idempotenz, das kleinste Ideal, Umbenennungen und den
Tafelcode zur Potenzhalbgruppe und zur endlichen Rekonstruktionssuche.
Ein Automorphismus dieses konkreten Potenzbeispiels vertauscht eine
Einermenge mit einer Zweiermenge. Die Nullprodukt-Rekonstruktion bleibt die
gesonderte Vertiefung des Spezialfalls mit Null und zwei Produktwerten;
beide Lesefassungen verlinken einander.

Die ergänzten Ableitungen wurden unabhängig auf mathematische Argumente,
Prämissen, Quantorenabschlüsse und Zeilenverweise geprüft. Die endlichen
Beispiele werden mit `scripts/check-finite-semigroups.py` vollständig
nachgerechnet: alle 16 Tafeln der Ordnung zwei, die acht assoziativen Tafeln,
ihre fünf Umbenennungsorbits und unterscheidenden Potenzinvarianten sowie
das Dreierbeispiel, sein kanonisches Minimum und sein Potenzautomorphismus.
Diese Rechnung und die technischen Verweisaudits sind keine allgemeine
maschinelle Prüfung der formalen Beweise.

Der Build der neuen Lesefassung und ihre Veröffentlichung sind in die
vorhandenen Nullprodukt- und Gesamtbuilds integriert. Die Lesefassung
importiert ausschließlich vorhandene Band-Aussagen; sie besitzt keine
konkurrierenden nummerierten Sätze. PDF-Verweise, lokale Zielmarken und
gerenderte Seiten werden vor der Aktualisierung unter `output/` geprüft.

Der erste Veröffentlichungs-Audit vom 2. Oktober prüfte 73 PDFs mit
6129 Seiten, 66029 lokalen und 46176 externen PDF-Verweisen. Zu diesem
Zwischenstand hatte der Gesamtband 2763 Seiten. Diese Zahlen beschreiben
den Stand vor der Zusammenführung mit den aktuellen Ergänzungen der
primären Ablage.

In den endgültigen Arbeitsstand wurden auch die dort bereits vorhandenen
Ergänzungen vom 1. Oktober übernommen. Band 28 enthält den weiterführenden
Hinweis zum allgemeinen Nullelement-Transport; Band 33 die ausgeschriebene
Profilgleichheit mit ihrem Tabellenbeweis. Die eigenständige Lesefassung
und die Beweistabellen zum Nullelement-Transport sind mit ihren Quellen,
Buildregistern und Veröffentlichungspfaden integriert. Die aktuelle
Nullprodukt-Lesefassung übernimmt diesen allgemeinen Nulltransport,
erklärt die Wahl und das Zusammenfügen der Faserbijektionen ausführlicher
und behält die seit dem 1. Oktober vorhandene Symbollegende samt Links
zu den Einführungsstellen bei. Ihr zusätzlicher Schlusslink führt zur
neuen Lesefassung über endliche Halbgruppen.

Die abschließenden Builds ergeben folgende Seitenzahlen:

| PDF | Seiten |
| --- | ---: |
| Gesamtband | 2765 |
| Band 37 – Endliche Halbgruppen | 86 |
| Endliche Halbgruppen erkennen – Lesefassung | 13 |
| Nullprodukt-Rekonstruktion – Beweistabellen | 35 |
| Nullprodukt-Rekonstruktion – Lesefassung | 37 |
| Nullelement-Transport – Beweistabellen | 16 |
| Nullelement-Transport – Lesefassung | 5 |

Band 37 und die neue Lesefassung enthalten keine überbreiten Zeilen.
Der Vergleich der Ergebnisregister und Satznummern zwischen Einzelbänden
und Gesamtband ist bestanden. Der endgültige gemeinsame
Veröffentlichungs-Audit prüft erfolgreich **75 PDFs mit 6161 Seiten,
66357 lokalen und 46669 externen PDF-Verweisen**.

Die drei Publisher-Kompatibilitätstests sind bestanden. Auch alle
17 Prüfungen der Symbollegende sind bestätigt, einschließlich
Seitenlayout, Linkflächen, Farbzustand und Fehlerdiagnosen. Drei absichtlich
fehlschlagende LaTeX-Beispiele wurden mit kürzeren Diagnosepräfixen
wiederholt, weil die langen Windows-Pfade die erwarteten Fehlermeldungen
im Protokoll mitten im Wort umbrechen. Die aktuelle Nullprodukt-Lesefassung
hat 54 verlinkte Einführungsstellen und 250 Symbolverweise. Ihre letzte
PDF-Seite wurde gerendert und auf die Symbollegende sowie die Navigation
zu Band 37, den Beweistabellen und der neuen Lesefassung geprüft.

## reMarkable-Veröffentlichung

Die fünf aktualisierten PDFs wurden am 2. Oktober auf reMarkable ersetzt;
die neue Lesefassung wurde ergänzt. Alle 75 aktiven PDFs stimmen bytegenau
mit dem endgültigen `output/` überein. Die Vorgänger und sämtliche bisherigen
Anmerkungsdateien sind erhalten. Der Cloud-Verbindungscheck meldet keine
Synchronisierungsfehler. Einzelheiten und Prüfnachweise stehen im
[reMarkable-Aktualisierungsbericht](remarkable-endliche-halbgruppen-aktualisierung-2026-10-02.md).
