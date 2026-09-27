# Frankls Spezialfälle: Lesefassung und Beweistabellen

Stand: 23. September 2026. Umsetzung des [Themenvorschlags](lesefassungen-pruefung-und-themenvorschlag-2026-09-23.md).

## Ergebnis

Die neue Lesefassung **„Warum ein Element in mindestens der Hälfte vorkommt – Frankls Vermutung bei kleinen Mengengliedern“** führt von einer konkreten Familie über den Einermengenfall zum vollständigen Zweiermengenbeweis. Ein kurzer Abschnitt behandelt den nichtleeren Durchschnitt. Eine Inzidenztafel, eine Vierfeldertafel und ein Diagramm der beiden Injektionszweige begleiten den Text. Die Zählgleichung und die Erklärung der Grenze beim Dreierfall runden das mathematische Argument ab.

Die letzten beiden Abschnitte sind ausdrücklich **Historischer Abriss** und anschließend **Schlussbemerkung**. Die Historie verweist auf van der Hout–Roos (2026) und Gilmers Originalarbeit (2022); Sarvate–Renaud (1989) werden anhand der Literaturangabe und Einordnung im erstgenannten Artikel genannt. Eine ungeprüfte Behauptung zur Erstentdeckung oder zum tagesaktuellen Forschungsstand wird nicht aufgestellt.

Die Lesefassung umfasst **11 PDF-Seiten einschließlich Titelblatt**, der Beweisband **15 PDF-Seiten einschließlich Titelblatt**. Beide liegen unter:

- [Lesefassung](<../output/02 Mengenlehre und Mengenfamilien/Ergänzungen/Frankls Spezialfälle/Bd. 46 - Frankls Spezialfälle - Lesefassung.pdf>)
- [Beweistabellen](<../output/02 Mengenlehre und Mengenfamilien/Ergänzungen/Frankls Spezialfälle/Bd. 46 - Frankls Spezialfälle - Beweistabellen.pdf>)

## Quellen und Aufteilung

Das neue Paket liegt unter `tex/b46/frankl/`; die beiden Einstiegspunkte unter `editions/`. Der Hauptband und der Beweisband verwenden dieselben Aussagen aus `statements.tex`. Nur Band 46 registriert diese Aussagen. Der Beweisband zeigt sie samt Voraussetzungen und Rückverweis, ohne sie ein zweites Mal zu registrieren. Die Lesefassung besitzt ebenfalls keine lokalen registrierten Sätze.

Ausgelagert wurden exakt **17 unveränderte Tabellenkörper**, bestehend aus 16 Satzbeweisen und einem Definitionsnachweis:

| Block | Tabellen |
| --- | ---: |
| Enthaltene Einermenge | 1 |
| Leere vermeidende Teilfamilie und nichtleerer Durchschnitt | 2 |
| Zerlegung und Disjunktheit der vier Klassen | 4 |
| Endlichkeit und Vergleich der gemischten Klassen | 2 |
| Paaradjunktion: Definition, Funktion, Auswertung, Injektivität | 4 |
| Zwei Beweiszweige und zwei abschließende Sätze | 4 |
| **Gesamt** | **17** |

Alle bisherigen Definitionen, Satzaussagen, Formelschlüssel, Nummern und Sprungziele bleiben in Band 46 erhalten. Die drei formelbasiert registrierten Sätze erhalten lediglich lokale Beweisanker mit den Namen `FranklSingletonMember`, `FranklAvoidingEmpty` und `FranklNonemptyIntersection`; diese Namen werden nicht zu neuen kanonischen Satzkennungen. Das Manifest sichert auch die ursprünglichen lokalen Abkürzungen vor den beiden Beweisen, die sie benötigen.

Die allgemeinen Grundlagen bleiben in ihren Fachbänden. Insbesondere stehen Funktionen in Band 05, Injektionen und Einermengenadjunktion in Band 06 und Vergleiche endlicher Mengen in Band 20. Die späteren Reduktionen und die Halbverbandsäquivalenz in Band 46 wurden nicht in diese Ergänzungen aufgenommen.

## Darstellung und Verknüpfung

Jede der 17 Aussagen im Hauptband verweist unmittelbar auf ihre Tabelle. Beide Ergänzungen verlinken Band 46 und einander; die Abschnittsverweise führen zu den jeweiligen Erläuterungen. Die Übersicht zu Band 46 sowie README und Bandverzeichnis erschließen die neuen Ausgaben.

Für die Darstellung wurden ausschließlich örtlich begrenzte Layoutanpassungen vorgenommen: Die Absatzüberschriften im verkürzten Fachband stehen oberhalb der folgenden Aussagen. Die lange Definitionsformel erhält bei Bedarf eine maßvoll verkleinerte Anzeige unter unverändertem Registrierschlüssel. Beim Injektivitätsbeweis bekommt die lange Schlussbegründung mehr Spaltenbreite. Der ursprüngliche mathematische Tabelleninhalt bleibt unverändert.

## Build und Prüfung

Der gezielte Aufruf lautet:

```powershell
pwsh -NoProfile -File ./scripts/build-frankl-editions.ps1
```

`-EditionsOnly` erzeugt und prüft die beiden Ergänzungen anhand vorhandener Fachbandartefakte; `-SkipMain`, `-SkipVolumeBuild` und `-SkipPublish` entsprechen dem bestehenden Editionsworkflow. `build-all.ps1` berücksichtigt die neuen Ausgaben nach Band 46 und seinen benötigten Vorgängern. Der Publisher unterstützt `--frankl`, schreibt die PDF-Verweise auf die veröffentlichten Pfade um und bezieht die Ergänzungen in seine Linkprüfung ein.

Die inhaltliche Prüfung des Lesebeweises erfolgte unabhängig von der Texterstellung. Kontrolliert wurden insbesondere Trägermitgliedschaft, Endlichkeit der Familie ohne unnötige Endlichkeit ihrer Mengenglieder, beide zusammengesetzten Injektionen, die Disjunktheit der Zielklassen, die Summenrechnung und die Abgrenzung beim Dreierfall. Die historischen Angaben wurden mit den angegebenen Publikationen abgeglichen.

Das Editionsaudit bestätigt die 17 unveränderten Aussagen und Tabellen samt Reihenfolge und Beweiskontexten, die ursprüngliche kanonische Registry einschließlich Formelschlüsseln, sämtliche ursprünglichen Nummern und Anker sowie leere lokale Register beider Ergänzungen. Die direkten Beweisverweise, Rückverweise und gegenseitigen PDF-Verknüpfungen sind geprüft. Ein unabhängiger Vergleich der extrahierten Quellen mit dem bisherigen Band bestätigt die unveränderte mathematische Substanz.

Alle Seiten der beiden Ergänzungen wurden gerendert und visuell geprüft; zusätzlich wurden die geänderten Seiten des Fachbands kontrolliert. Die beiden neuen Ausgaben enthalten keine Overfull-/Underfull-Meldungen oder undefinierten Verweise. Im übrigen Fachband vorhandene Layoutmeldungen außerhalb des bearbeiteten Spezialfallblocks werden durch diese Auslagerung nicht zu einer Gesamtprüfung aller übrigen Seiten.

Nach der Veröffentlichung wurden alle 26 Seiten der beiden Ergänzungen erneut gerendert und mit den geprüften Build-PDFs verglichen. Die Seitenbilder sind pixelgleich; die auf die Ausgabeordner umgeschriebenen Verknüpfungen bestehen die Linkprüfung.

Auch Überblick, Band 46 und der Gesamtband wurden neu gebaut. Der Gesamtband umfasst 2.655 PDF-Seiten. Das abschließende Referenzaudit für `B00`, `B46` und `main` besteht; es gleicht für alle Fachbände die Register und Satznummern des Gesamtbands mit den Einzelausgaben ab. Die geänderten Darstellungen wurden zusätzlich an drei Seiten des Gesamtbands visuell kontrolliert.

Die abschließende Veröffentlichung aller fünf aktualisierten PDFs ist abgeschlossen. Die Linkprüfung des gesamten Ausgabeordners besteht für 66 PDFs mit 5.760 Seiten, 61.808 internen und 41.354 dateiübergreifenden Verweisen.

Die automatischen Prüfungen sichern Quellen-, Nummern- und Verweisintegrität. Sie sind keine maschinelle Zertifizierung der mathematischen Schlussregeln.
