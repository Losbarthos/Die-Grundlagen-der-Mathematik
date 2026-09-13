# Nummerierung von Theoremaussagen: Bände 15–18 und 20–27

## Ergebnis

20 bisher unnummerierte Familien mit zusammen 50 Schlussaussagen erhielten sichtbare Kennzeichnungen `(i)`, `(ii)`, … . Die Aussagen stehen einzeln untereinander. Gemeinsame Voraussetzungen bleiben als gemeinsamer Vorspann erhalten; bei der monotonen Konvergenz gehören die jeweils unterschiedlichen Voraussetzungen weiterhin zum betreffenden nummerierten Schluss.

| Band | geprüfte FormulaThm-Aufrufe | geänderte Familien | nummerierte Aussagen |
| --- | ---: | ---: | ---: |
| 15 | 23 | 0 | 0 |
| 16 | 11 | 0 | 0 |
| 17 | 89 | 1 | 2 |
| 18 | 65 | 3 | 6 |
| 20 | 189 | 0 | 0 |
| 21 | 56 | 12 | 32 |
| 22 | 18 | 0 | 0 |
| 23 | 7 | 0 | 0 |
| 24 | 4 | 0 | 0 |
| 25 | 2 | 0 | 0 |
| 26 | 64 | 4 | 10 |
| 27 | 75 | 0 | 0 |
| **Gesamt** | **603** | **20** | **50** |

Die Quellen enthalten in diesem Umfang keine klassischen theorem-, thm-, Satz-, Proposition- oder Lemma-Umgebungen. Die 603 syntaktischen FormulaThm-Aufrufe schließen im Quelltext vorhandene inaktive Altabschnitte ein; alle vorgenommenen Änderungen betreffen aktive Theoreme. Band 19 liegt beim anderen Prüfer.

## Geänderte Familien

| Band | ursprüngliche Zeile | ID | Aussagen |
| --- | ---: | --- | ---: |
| 17 | 3240 | IntegerMulZeroFromAxioms | 2 |
| 18 | 609 | RationalZeroOneClasses | 2 |
| 18 | 655 | RationalZeroOneCarrier | 2 |
| 18 | 875 | RationalNegationLaws | 2 |
| 21 | 329 | IndexedFamilyRestrictionFacts | 3 |
| 21 | 825 | FiniteSequenceIndexShiftBijective | 2 |
| 21 | 935 | FiniteSequenceConventionConversion | 2 |
| 21 | 2411 | MonotoneRealSequenceConvergence | 2 |
| 21 | 3615 | MogiljanskajaReserveMarkerFacts | 5 |
| 21 | 3928 | MogiljanskajaReserveCoreFacts | 2 |
| 21 | 3969 | MogiljanskajaRowParametrizationsBijective | 2 |
| 21 | 4198 | MogiljanskajaShiftSequenceFacts | 3 |
| 21 | 4276 | MogiljanskajaShiftSequenceImage | 2 |
| 21 | 4420 | MogiljanskajaVParametrizationBijective | 2 |
| 21 | 4523 | MogiljanskajaDPrimeParametrizationBijective | 2 |
| 21 | 4601 | MogiljanskajaFamilyImages | 5 |
| 26 | 2808 | ForestAccess | 2 |
| 26 | 3119 | TreeAccess | 3 |
| 26 | 3638 | TreeParentAccess | 3 |
| 26 | 4473 | OrderedFullBinaryTreeAccess | 2 |

Das vollständige maschinenlesbare Inventar mit Titeln, Originalformeln und neuen Anzeigen liegt in `b15-b27-changes.json`. Eigene Ausgangskopien liegen unter `b15-b27-before/`; die ausschließlich diesen Nummerierungsschritt enthaltenden Diffs heißen `b17-numbering.diff`, `b18-numbering.diff`, `b21-numbering.diff` und `b26-numbering.diff`.

## Geprüfte Abgrenzung

Der grobe Suchlauf erfasste 461 mögliche Kandidaten mit Kommas, `\dsep` oder Displayzeilen. Die semantische Nachprüfung unterschied Schlussfamilien von Prämissen und einzelnen Formeln. Insbesondere blieben unverändert:

- Kommagetrennte Variablen, Argumente und gemeinsame Zugehörigkeitsangaben, etwa `x,y\in A` beziehungsweise `\lambda(x),\rho(x)\in Children(x)`.
- Existenz- und Eindeutigkeitsaussagen mit mehreren gemeinsam gebundenen Eigenschaften; dazu gehören die Quotientenabstiege in Band 17/18 und zahlreiche Typisierungs- und Konstruktionstheoreme in Band 20/27.
- Einzelne ausdrückliche Konjunktionen, Äquivalenzen und Gleichheitsketten. Beispielsweise bleiben die gebündelten Nachbarschaftskriterien in Band 22 eine Konjunktionsaussage, ebenso Strukturzugriffe in Band 24/25 und entsprechende Baumcharakterisierungen.
- Bereits sichtbar nummerierte Aussagefamilien.

Die bisher mehrspaltig und durch Kommas getrennten fünf Mogiljanskaja-Bildmengengleichungen wurden ausdrücklich in fünf nummerierte Zeilen überführt. Die Markerfamilie enthält fünf inhaltliche Aussagen; die jeweiligen Listen `c_0,c_1,c_2` sind dabei weiterhin gemeinsame Argumentlisten derselben Aussage.

## Referenz- und Änderungsintegrität

Alle 20 Änderungen verwenden das zentral neu bereitgestellte Makro

`\FormulaThmDeltaKR[Titel]{neue Anzeige}{Original-Strukturformel}{Original-ID}{Delta-Zeilen}`.

Original-Strukturformeln und IDs wurden unverändert übernommen. Eine parsergestützte Rücktransformation sämtlicher neuer KR-Aufrufe zu den ursprünglichen K-Aufrufen stellte die Ausgangsdateien vollständig wieder her. Damit sind insbesondere Beweiszeilen, Hilfsteilnummern, Delta-Zeilen, Referenzen und alle Inhalte außerhalb der geänderten Anzeigen exakt erhalten. Das Ergebnis steht in `b15-b27-verification.json`.

Es wurden keine Builds gestartet und keine PDFs verändert. Die geänderten Quellen in Band 17, 18, 21 und 26 sind für den zentral koordinierten Build bereit.
