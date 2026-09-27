# Gruppenrekonstruktion: Lesefassung und Beweistabellen

Stand: 24. September 2026. Umsetzung des bestätigten [Themenvorschlags](lesefassungen-pruefung-und-themenvorschlag-2026-09-24.md).

Nachtrag vom 25. September 2026: Die [Einarbeitung der Randanmerkungen und die Ergänzung zur Potenzhalbgruppenvermutung](gruppenrekonstruktion-lesefassung-anmerkungen-2026-09-25.md) sind separat dokumentiert. Die folgenden Seitenzahlen beschreiben den ursprünglichen Stand der Auslagerung.

## Ergebnis

Die Lesefassung **„Wie man eine Gruppe in ihren Mengenprodukten wiedererkennt – Einermengen, Einheiten und Gruppenrekonstruktion“** beginnt mit der vollständigen Multiplikationstafel der nichtleeren Teilmengen einer Zweiergruppe. Sie entwickelt daraus zwei Beweisstufen: Zunächst werden zwei Gruppen aus ihren isomorphen Potenzhalbgruppen rekonstruiert. Anschließend wird bewiesen, dass auf der zweiten Seite bereits die Voraussetzung einer Halbgruppe genügt.

Der Text erklärt alle tragenden Argumente in Prosa und mit einzelnen Rechnungen: invertierbare Einermengen, Transport durch einen Isomorphismus, Existenz des neutralen Elements in der Zielhalbgruppe, Stabilität unter Einheiten, das Bild der gesamten Einheitenmenge und schließlich das Produktkriterium für ihre nichtleeren Teilmengen. Die Unterscheidung zwischen dem Bild einer einzelnen Menge und dem Bild einer ganzen Mengenfamilie wird ausdrücklich erläutert.

Die beiden letzten inhaltlichen Abschnitte heißen **Historischer Abriss** und **Schlussbemerkung**. Danach folgt kein weiterer Abschnitt. Die Lesefassung umfasst **13 PDF-Seiten einschließlich Titelblatt**, der Beweisband **20 PDF-Seiten einschließlich Titelblatt**.

- [Lesefassung](<../output/08 Gruppen/Ergänzungen/Gruppenrekonstruktion/Bd. 40 - Gruppenrekonstruktion - Lesefassung.pdf>)
- [Beweistabellen](<../output/08 Gruppen/Ergänzungen/Gruppenrekonstruktion/Bd. 40 - Gruppenrekonstruktion - Beweistabellen.pdf>)

## Auslagerung

Zwölf Aussagen werden aus `tex/b40/reconstruction/statements.tex` gemeinsam verwendet. Nur Band 40 registriert sie. Der Beweisband stellt die ursprünglichen Aussagen mit ihren Voraussetzungen dar und importiert ihre kanonischen Verweise. Die zwölf zugehörigen Tabellenkörper wurden aus Band 40 nach `tex/b40/reconstruction/proofs.tex` verschoben:

| Nummer | Aussage / Kennung |
| --- | --- |
| 40.3.3.2 | `PowerGroupUnitsAreSingletons` |
| 40.3.3.3 | `PowerGroupsSingletonLayer` |
| 40.3.3.4 | `PowerGroupsSingletonTransport` |
| 40.3.3.10 | `GroupPowerFullCarrierAbsorption` |
| 40.3.3.11 | `SemigroupIsoUnitStabilityTransport` |
| 40.3.3.12 | `PowerMonoidUnitSetStable` |
| 40.3.3.13 | `PowerMonoidUnitStableAbsorption` |
| 40.3.3.14 | `PowerMonoidUnitSubsetCriterion` |
| 40.3.3.15 | `LargePowerUnitSetImage` |
| 40.3.3.16 | `LargePowerUnitSubsetImage` |
| 40.3.3.18 | `LargePowerSemigroupUnitGroupReconstruction` |
| 40.3.3.19 | `GroupPowerSemigroupRigidity` |

Der im Absorptionsbeweis enthaltene Hilfssatz `GroupPowerFullCarrierAbsorptionProductMember` behält seinen ursprünglichen registrierten Anker und die Nummer **40.3.3.10 (H1)** in Band 40. Die Beweisedition zeigt ihn mit importiertem Verweis. Damit bleiben auch Verweise auf dieses innere Ergebnis erhalten.

Sieben allgemeine Tabellen bleiben unverändert in Band 40: `GroupElementIsMonoidUnit`, `MonoidUnitSetInverse`, `MonoidInversePairProduct`, `MonoidUnitSetProduct`, `MonoidUnitSetCarrier`, `MonoidUnitSetIsGroup` und `GroupUnitSetIsCarrier`. Die allgemeinen Monoidgrundlagen in Band 38 bleiben ebenfalls an ihrem bisherigen Ort. Band 40 umfasst nach der Auslagerung **27 PDF-Seiten**.

Das Manifest `scripts/reconstruction-manifest.json` enthält die ursprünglichen Aussagen, Tabellenkörper, Registry-Einträge und Nummern samt PDF-Zielen. Das Quellaudit vergleicht die mathematischen Körper bis auf Kommentare und Leerraum. Örtliche Darstellungsanpassungen liegen außerhalb dieser Körper: Die längste Aussage wird etwas kleiner gesetzt, eine lange Tabellenzeile an ihrer vorhandenen Konjunktion umbrochen und Überschriften werden gegen alleinstehende Platzierung am Seitenende geschützt.

## Inhalt und historische Einordnung

Eine unabhängige inhaltliche Prüfung hat beide Beweisstufen und ihren Übergang kontrolliert. Besonders geprüft wurden die Monoidvoraussetzung beim Einheitenargument, die zunächst unbekannte Neutralität in der Zielhalbgruppe, beide Richtungen des Isomorphismus beim Nachweis des Einheitenmengenbildes sowie das Produktkriterium, das ohne vorausgesetzte Inklusionstreue auskommt.

Der erste Beweis benötigt nur Einermengen und funktioniert auch für die Potenzhalbgruppen der endlichen nichtleeren Teilmengen. Der ausgeführte stärkere Beweis verwendet dagegen die gesamte, möglicherweise unendliche Einheitenmenge. Diese Grenze wird ausdrücklich genannt. Ebenfalls wird nicht behauptet, der vorgegebene Isomorphismus wirke auf jeder Teilmenge punktweise durch den rekonstruierten Gruppenisomorphismus.

Der historische Abriss trennt den älteren Zweigruppensatz vom stärkeren Satz mit nur einer vorausgesetzten Gruppe. Die Einordnung stützt sich auf:

- Tamura–Shafer, *Power semigroups* (1967), sowie das [Forschungsabstract 648-194](https://www.ams.org/journals/notices/196708/196708FullIssue.pdf), S. 688, für den endlichen Fall. Die Zuordnung des allgemeinen Zweigruppensatzes zu Shafers *Note on power semigroups* (1967) wird ausdrücklich über Liu–Tringali belegt.
- Mogiljanskaja, [*Non-isomorphic semigroups with isomorphic semigroups of subsets*](https://doi.org/10.1007/BF02389140) (1973), als Grenze der allgemeinen Rekonstruktionsfrage.
- Liu–Tringali, [*Power Semigroups and Two Rigidity Theorems for Groups*](https://arxiv.org/html/2606.01917v1) (2026), insbesondere Theorem 1.3 und Theorem 2.3, für den stärkeren Satz und den Transport der Einheitenmenge samt Teilmengenfamilie.

Die Lesefassung unterscheidet diese historische Zuordnung von ihrer eigenen didaktischen Anordnung und Beweisführung.

## Build und Integration

Der vollständige gezielte Aufruf lautet:

```powershell
pwsh -NoProfile -File ./scripts/build-reconstruction-editions.ps1
```

Der Builder erzeugt Band 40, die beiden Ergänzungen, den Überblick und den Gesamtband, prüft die Ergebnisse und veröffentlicht die fünf PDFs im vorhandenen Ausgabeordner. Die Optionen `-EditionsOnly`, `-SkipVolumeBuild`, `-SkipMain` und `-SkipPublish` ermöglichen die entsprechenden Teilschritte. Die editionsbezogenen Prüfungen lassen sich gesondert ausführen:

```powershell
python ./scripts/reconstruction-editions.py audit
```

`build-all.ps1` berücksichtigt die Ergänzungen nach den ausgewählten Abhängigkeiten von Band 40. Der Publisher unterstützt `--reconstruction`, schreibt die dateiübergreifenden PDF-Verweise auf die Ausgabeordner um und prüft die Ergänzungen auch bei späteren eingeschränkten Publikationsläufen. Die allgemeine Quellinventur erfasst die ausgelagerten Dateien. README, Bandverzeichnis, Build-Anleitung und die Übersicht zu Band 40 erschließen die neuen Ausgaben.

Die automatischen Prüfungen sichern die Erhaltung der Quellen, Kennungen, Nummern und Sprungziele. Sie sind keine maschinelle Zertifizierung der mathematischen Schlussregeln.

## Prüfung der Ausgaben

Der gezielte Builder wurde mit den bereits erneuerten Fachbandartefakten ausgeführt. Das Editionsaudit bestätigt alle zwölf unveränderten Originalaussagen und Tabellenkörper, den erhaltenen inneren Hilfssatz, die sieben unveränderten Grundlagenbeweise, sämtliche kanonischen Nummern und Ziele sowie leere lokale Register beider Ergänzungen. Direkte Beweislinks, Rückverweise und gegenseitige Verknüpfungen bestehen die PDF-Prüfung. Die allgemeine Quellinventur findet keine ungültigen Steuerzeichen.

Alle 33 Seiten der beiden Ergänzungen wurden gerendert und visuell geprüft. Auch der geänderte Abschnitt in Band 40 wurde vollständig gesichtet; nach den letzten Umbruchkorrekturen wurden die betroffenen Seiten erneut kontrolliert. Beide Ergänzungen und Band 40 enthalten keine Overfull-/Underfull-Meldungen, fehlenden Zeichen oder undefinierten Verweise. Das Referenzaudit für B00, B40 und den auf Band 40 verweisenden Band 42 besteht.

Nach der Veröffentlichung wurden alle 33 Seiten der beiden Ergänzungen nochmals gerendert. Ihre Seitenbilder sind pixelgleich mit den visuell geprüften Build-PDFs. Die Umschreibung auf die endgültigen PDF-Pfade verändert somit nur die Verknüpfungen, nicht die gesetzten Seiten.

Auch Überblick, Band 40 und der Gesamtband wurden neu gebaut und in den Ausgabeordner übernommen. Der Gesamtband umfasst **2.643 PDF-Seiten**. Das abschließende Referenzaudit für B00, B40, B42 und `main` besteht. Es gleicht insbesondere die Ergebnisregister und Satznummern sämtlicher Fachbände zwischen Gesamtband und Einzelausgaben ab. Die neue Überblickspassage und drei repräsentative Seiten des geänderten Gruppenabschnitts wurden auch im Gesamtband visuell kontrolliert.

Die vier kontrollierten Gesamtbandseiten sind nach der Veröffentlichung ebenfalls pixelgleich mit dem geprüften Satz. Die abschließende Linkprüfung des vollständigen Ausgabeordners besteht für **68 PDFs mit 5.790 Seiten, 61.393 internen und 41.722 dateiübergreifenden Verweisen**. Alle fünf betroffenen Ausgaben sind aktualisiert.
