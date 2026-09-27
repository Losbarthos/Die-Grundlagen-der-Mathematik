# Nullprodukt-Rekonstruktion: vierte Anmerkungsrunde

Grundlage ist die am 27. September 2026 erneut bereitgestellte, 26-seitige Datei `Band 37 - Nullprodukt-Rekonstruktion - Lesefassung.pdf` aus dem Downloads-Ordner. Die handschriftlichen Ergänzungen auf PDF-Seiten 4–7 (Druckseiten 3–6) wurden visuell gelesen. Das letzte Häkchen steht beim abgeschlossenen Bijektivitätsbeweis für Φ₂; ab dem Rückschluss von drei Produktmengen auf zwei Produktwerte fehlen weitere Häkchen. Der gesamte anschließende Text wurde deshalb auf entsprechende Erklärungs- und Begründungslücken geprüft.

## Anmerkungen und Änderungen

| Anliegen | Umsetzung |
| --- | --- |
| Welche sieben Elemente sind gemeint? | Eine Tabelle listet alle sieben nichtleeren Teilmengen von `{0,c,a}` auf. Sie unterscheidet ausdrücklich die Grundelemente von den Elementen der Potenzhalbgruppe. |
| Warum kann man aus der Mengenanzahl auf die Grundelementanzahl schließen? | Die Übersicht erklärt `2^n−1`, die strenge Zunahme und die Voraussetzung, dass sämtliche nichtleeren Teilmengen der betreffenden Grundmenge gezählt werden. Drei beliebige Teilmengen erlauben diesen Rückschluss nicht. |
| Was ist ein Nulltest? | Der Begriff wird vor seiner ersten Verwendung mit linker und rechter Multiplikation erklärt. Ein späteres Beispiel rechnet einen bestandenen und einen nicht bestandenen Test aus. |
| Unnötige Erläuterung zur äußeren Hochzahl 2 | Der ausdrücklich markierte Satz wurde entfernt. |

Auch die Rechnung `3−2=1` bezeichnet nun eindeutig Grundelementanzahlen. Die Übersicht nennt ausdrücklich die noch zu beweisenden Voraussetzungen für dieselbe Zählung auf der Zielseite.

## Prüfung und Ergänzungen hinter dem letzten Häkchen

- Beim Rückschluss auf zwei Produktwerte wird erklärt, dass auch die gesamte Menge T² nur ein Mitglied der Ergebnisfamilie ist.
- Bei der Gewinnung der Zielnull wird ihre Zugehörigkeit zu T² ausdrücklich nachgewiesen. Der Übergang von Idempotenz für Teilmengen zur Idempotenz ihrer Grundelemente erfolgt sichtbar über Einermengen.
- Nulltests werden durch einzelne Testmengen erläutert. Die Ordnung der Profile beruht auf einer Implikation für jeden Test, nicht auf einem bloßen Vergleich der Anzahlen bestandener Tests.
- Das Profil eines Grundelements wird als Profil seiner Einermenge erklärt. Beim Isomorphietransfer werden die untersuchte Menge und die Testmenge beide abgebildet.
- Das Dreierbeispiel zeigt, warum ein einzelnes Profil noch keine vollständige nichtleere Potenzmenge sein muss und warum die kleineren Profile hinzugenommen werden.
- Im eigentlichen Zählbeweis stehen die vollständigen Gleichungsketten auch für die Zielmengen. Erst die zuvor bewiesene Potenzmengenidentität erlaubt den Rückschluss von drei beziehungsweise sieben Teilmengen auf zwei beziehungsweise drei Grundelemente.
- Beim Abziehen kleinerer Fasern wird wieder ausdrücklich gesagt, dass Grundelemente gezählt werden. Für ein minimales Profil ist die verwendete Hilfsbijektion die leere Bijektion.
- Das abschließende Gegenbeispiel unterscheidet eindeutig zwischen drei Produktwerten und seinen fünf Grundelementen.

Die unabhängige mathematische Gegenprüfung fand keine verbleibende Beweislücke in den überarbeiteten Argumenten. Die zusätzlichen Erläuterungen verwenden vorhandene Aussagen, insbesondere `FiniteNonemptyPowerSetCardinality`, `FiniteNonemptyPowerSetReflectsCardinality` und `PeanoPowerTwoStrictMonotoneInjective`. Sie stimmen mit der Rekonstruktion in Band 33 und den Beweistabellen von Band 37 überein. Zusätzliche Axiome, Bände oder Änderungen der Beweistabellen waren nicht erforderlich.

## Ausgabe und Prüfung

Geändert wurde `tex/b37/nullproducts/reading.tex`. Die Lesefassung wurde neu gebaut und umfasst jetzt 28 PDF-Seiten. Alle Seiten wurden visuell geprüft. Drei ungünstige Schlussumbrüche wurden korrigiert; die danach veränderten Seiten 24–28 wurden erneut gerendert und vollständig geprüft. Formeln sind vollständig lesbar, Beispielkästen bleiben auf einer Seite, Überschriften und Absatzanfänge stehen mit ausreichendem Folgetext zusammen.

Der endgültige Bau enthält keine übervollen oder untervollen Boxen und keine ungelösten Verweise. Es bleiben nur die bereits bekannten Paketwarnungen zum Spaltentyp W und zur deutschen Silbentrennung. Die Editionsprüfung bestätigt Quellenzuordnung, Satznummern und Verweise für die 28-seitige Lesefassung und die unveränderten 35-seitigen Beweistabellen. Die vorhandene Prüfung von 23 kleinen Halbgruppentafeln und drei ausgearbeiteten Beispielen wurde ebenfalls erfolgreich ausgeführt.

Veröffentlicht wurde ausschließlich die Lesefassung im bisherigen Ausgabeordner. Die übrigen 69 PDFs sind gegenüber dem Rundenbeginn SHA256-identisch. Der Veröffentlichungsschritt prüft unveränderte Seiteninhalte, Seitengrößen und benannte Sprungziele gegenüber dem geprüften Bau sowie alle umgeschriebenen externen PDF-Ziele. Sämtliche 49 bisherigen benannten Sprungziele der Lesefassung bleiben erhalten. Ein erneuter vollständiger Audit aller übrigen, unveränderten PDFs wurde in dieser Runde nicht ausgeführt.

Das angehängte Original, der Ausgangsstand der Lesefassung, Bauprotokoll, Seitenbilder und Veröffentlichungsnachweis liegen unter `tmp/pdfs/nullproducts-annotations-round4-2026-09-27/`. Andere bestehende Inhalte, lokale Änderungen und frühere Prüfberichte bleiben erhalten. Der reMarkable-Abgleich wird separat dokumentiert.
