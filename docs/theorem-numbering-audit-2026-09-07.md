# Teilnummerierung der Theoremfolgen – 7. September 2026

Die Quellprüfung umfasst die Bände 00 bis 44 und die aktive Isomorphiesammlung in `tex/B28-isomorphism-examples.tex`. Insgesamt wurden 2.708 Theoremdeklarationen erfasst. Band 00 samt seinen Eingabedateien enthält keine Theoreme.

In 58 Theoremfamilien waren mehrere unabhängig aufgelistete Schlussaussagen noch nicht einzeln nummeriert. Diese erhalten insgesamt 192 sichtbare Teilnummern `(i)`, `(ii)` usw. Kommagetrennte Aussagen derselben Zeile sind einbezogen. Prämissenlisten, gebundene Variablenlisten, Gleichheitsketten und ausdrücklich konjunktive Einzelaussagen bleiben zusammen. Bereits vorhandene Teilnummerierungen bleiben erhalten.

| Band | Geänderte Familien | Nummerierte Aussagen |
| --- | ---: | ---: |
| 05 | 1 | 2 |
| 10 | 1 | 2 |
| 17 | 1 | 2 |
| 18 | 3 | 6 |
| 19 | 7 | 30 |
| 21 | 12 | 32 |
| 26 | 4 | 10 |
| 28 | 29 | 108 |

## Das gemeldete Theorem

Theorem **28.2.15.3 – Transport von Unterhalbgruppen und Idealen** (`SemigroupIsoSubstructureTransport`) hat jetzt vier Teilnummern: Unterhalbgruppen, Linksideale, Rechtsideale und zweiseitige Ideale. Seine Theoremnummer bleibt unverändert.

## Erhaltung der Verweise

Das neue Makro `FormulaThmDeltaKR` trennt die sichtbare nummerierte Darstellung von der bisherigen strukturellen Referenzformel. Alle 58 Original-Strukturargumente und alle expliziten IDs bleiben exakt erhalten.

Eine zusätzliche Kollision betraf Hauptaussagen und registrierte Hilfssätze: Beide verwendeten bisher dieselben römischen Suffixe. Die registrierten Hilfssätze tragen jetzt bandübergreifend `(H1)`, `(H2)` usw.; die Hauptaussagen behalten `(i)`, `(ii)` usw. Die eigentlichen Theoremnummern, technischen Labels, Zählerstände und Linkziele bleiben bestehen. Band 1 erläutert diese Unterscheidung. Die Suche nach hart codierten römischen Hilfssatzverweisen ergab keinen umzuschreibenden internen Textverweis. Die Aussagen eines kurzen Familienblocks werden gemeinsam mit Überschrift und Delta-Kontext gesetzt; das verhindert eine Trennung über einen Seitenwechsel.

Bei `SemigroupIsoIdentitiesZerosUnits` werden die gleichwertigen Bedingungen für neutrale Elemente und Nullen in der Anzeige als explizite Konjunktionen geschrieben. Damit stimmt die sichtbare Matrix exakt mit dem bewiesenen Hilfssatz überein. Das bisherige Strukturargument bleibt auch dort erhalten.

## Geänderte Familien

| Theorem | Schlüssel | Teilnummern |
| --- | --- | ---: |
| 5.3.2.22 | `CompatibleFunctionGraphFamilyUnion` | 2 |
| 10.5.1.7 | `PeanoPowerTwoStrictMonotoneInjective` | 2 |
| 17.2.7.1 | `IntegerMulZeroFromAxioms` | 2 |
| 18.2.3.6 | `RationalZeroOneClasses` | 2 |
| 18.2.3.7 | `RationalZeroOneCarrier` | 2 |
| 18.3.1.4 | `RationalNegationLaws` | 2 |
| 19.4.1.3 | `RealCutAdditiveLaws` | 4 |
| 19.4.1.4 | `RealCutNegationOrder` | 4 |
| 19.4.2.1 | `RealCutMultiplicativeClosure` | 4 |
| 19.4.2.4 | `RealCutMultiplicativeLaws` | 5 |
| 19.4.3.1 | `RationalToRealEmbeddingArithmetic` | 4 |
| 19.5.1.1 | `RealAbsoluteValueLaws` | 5 |
| 19.5.1.2 | `RealDistanceLaws` | 4 |
| 21.2.3.2 | `IndexedFamilyRestrictionFacts` | 3 |
| 21.3.3.2 | `FiniteSequenceIndexShiftBijective` | 2 |
| 21.3.3.3 | `FiniteSequenceConventionConversion` | 2 |
| 21.5.4.3 | `MonotoneRealSequenceConvergence` | 2 |
| 21.6.2.2 | `MogiljanskajaReserveMarkerFacts` | 5 |
| 21.6.2.3 | `MogiljanskajaReserveCoreFacts` | 2 |
| 21.6.3.1 | `MogiljanskajaRowParametrizationsBijective` | 2 |
| 21.6.4.2 | `MogiljanskajaShiftSequenceFacts` | 3 |
| 21.6.4.3 | `MogiljanskajaShiftSequenceImage` | 2 |
| 21.6.5.1 | `MogiljanskajaVParametrizationBijective` | 2 |
| 21.6.5.3 | `MogiljanskajaDPrimeParametrizationBijective` | 2 |
| 21.6.5.4 | `MogiljanskajaFamilyImages` | 5 |
| 26.3.1.2 | `ForestAccess` | 2 |
| 26.3.2.2 | `TreeAccess` | 3 |
| 26.4.2.1 | `TreeParentAccess` | 3 |
| 26.5.3.2 | `OrderedFullBinaryTreeAccess` | 2 |
| 28.2.16.8 | `MogiljanskajaPowerProductFormula` | 2 |
| 28.2.16.9 | `MogiljanskajaReserveMapProperties` | 5 |
| 28.3.1.1 | `MogiljanskajaArgumentM1WellDefined` | 8 |
| 28.3.1.2 | `MogiljanskajaArgumentM2Semigroups` | 7 |
| 28.3.1.4 | `MogiljanskajaArgumentM4ProductStatus` | 2 |
| 28.3.2.1 | `MogiljanskajaArgumentM6ProductClassification` | 4 |
| 28.3.2.2 | `MogiljanskajaArgumentM7AbsorptionHypotheses` | 5 |
| 28.3.2.3 | `MogiljanskajaArgumentM8PsiBijective` | 3 |
| 28.3.2.4 | `MogiljanskajaArgumentM9EtaBijective` | 3 |
| 28.3.2.5 | `MogiljanskajaArgumentM10EtaFixedPart` | 2 |
| 28.3.3.1 | `MogiljanskajaArgumentM12PhiBijective` | 5 |
| 28.3.3.2 | `MogiljanskajaArgumentM13PhiInvariants` | 3 |
| 28.3.3.3 | `MogiljanskajaArgumentM14ProductPartsInvariant` | 3 |
| 28.2.15.2 | `SemigroupIsoElementaryTransport` | 6 |
| 28.2.15.3 | `SemigroupIsoSubstructureTransport` | 4 |
| 28.2.15.6 | `SemigroupCarrierPowersCalculus` | 3 |
| 28.2.15.7 | `SemigroupIsoPositiveCarrierPowers` | 2 |
| 28.2.15.8 | `SemigroupIsoGeneratedSubsemigroups` | 4 |
| 28.2.15.10 | `SemigroupIsoPrincipalIdealsAndGreen` | 3 |
| 28.2.15.14 | `SemigroupIsoDirectProducts` | 3 |
| 28.2.15.18 | `SemigroupCanonicalProductIsomorphisms` | 5 |
| 28.2.15.20 | `SemigroupIsoCentralizers` | 4 |
| 28.2.15.21 | `SemigroupIsoLocalCarriers` | 3 |
| 28.2.15.22 | `SemigroupIsoIdentitiesZerosUnits` | 3 |
| 28.2.15.23 | `SemigroupIsoFreshAdjunctions` | 5 |
| 28.2.15.24 | `SemigroupIsoCongruenceQuotients` | 2 |
| 28.2.15.26 | `SemigroupIsoEndomorphismConjugation` | 2 |
| 28.2.15.27 | `SemigroupIsoSubstructureOrders` | 4 |
| 28.2.15.28 | `SemigroupIsoEquationSolutionTransport` | 3 |

## Validierung

Abgeschlossen: Alle 58 Original-Strukturargumente und IDs sind exakt erhalten; die 192 sichtbaren Teilnummern sind jeweils vollständig und fortlaufend. Die aktuelle Quellenprüfung wurde unabhängig wiederholt. Alle 58 geänderten Aussagenanzeigen wurden in den Einzelband-PDFs visuell geprüft; festgestellte Titel-, Formel- und Begründungsumbrüche wurden korrigiert und nachgeprüft.

Alle 45 Einzelbände (00–44) und der Gesamtband wurden neu gebaut. Ihre Register, sichtbaren Nummern und Linkziele sind abgeglichen; 929 registrierte Hilfssätze besitzen die erwarteten H-Kennzeichnungen und unveränderten technischen Anker, ohne doppelte Hilfslabels. Die 46 veröffentlichten PDFs im Ordner `output` haben die vollständige Prüfung ihrer lokalen und bandübergreifenden Verweise bestanden.

Die [dauerhaften Prüfbelege](assets/theorem-numbering-audit-2026-09-07/README.md) enthalten aktuelle Anzeigen, Originalreferenzen, wiederholbare Quellen-/Hilfsnummernprüfer, Sichtprüfberichte, Buildprotokolle und das [abschließende Build- und Linkergebnis](assets/theorem-numbering-audit-2026-09-07/final-build-verification.json). Kleine bereits vorhandene Satzwarnungen werden nicht als vollständige Warnungsfreiheit ausgegeben.

## Abgrenzung zur Beweisregelprüfung

Die zuvor beauftragte Suche nach metasprachlichen Tabellenbegründungen führte zusätzlich zu tatsächlichen Regelkorrekturen und ausformulierten Beweisen. Sie ist nicht mit einer maschinellen Verifikation aller mathematischen Beweise gleichzusetzen. In den Bänden 19, 26, 27, 28, 31 und 37 bestehen weiterhin umfangreichere fachliche Formalisierungslücken; diese werden im gesonderten [Beweisregelbericht](proof-rules-audit-2026-09-07.md) ausdrücklich dokumentiert. Die vollständige Beseitigung sämtlicher solcher Lücken ist noch nicht abgeschlossen.
