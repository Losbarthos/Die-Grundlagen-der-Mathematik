# Formalisierung der letzten drei Isomorphiefamilien in Band 28

## Umfang und Ergebnis

Bearbeitet wurden ausschließlich die Beweisteile der Familien `SemigroupIsoEndomorphismConjugation`, `SemigroupIsoSubstructureOrders` und `SemigroupIsoEquationSolutionTransport` in `tex/B28-isomorphism-examples.tex`. Ihre Theorem-Anzeigen einschließlich Originalstrukturformeln/IDs blieben unberührt. Jede Änderung las vor dem Schreiben den aktuellen Dateistand und ersetzte nur den eigenen, unverändert wiedergefundenen Teilblock; parallele Änderungen anderer Agenten blieben erhalten.

Die acht vorhandenen Teilbeweise wurden von insgesamt 228 auf 461 Schritte erweitert; hinzu kommen zwei eigenständig bewiesene Relationshilfen mit 76 Schritten. Insgesamt wurden 537 Schritte in zehn Teilbeweisen statisch geprüft. Keine Builds gestartet und keine PDFs geändert.

## Ausgearbeitete Schlussstellen

- Konjugation: Endomorphismen-/Automorphismenabschluss mit expliziter Quantifizierung; Automorphismen als Teilmenge der Endomorphismen mit direktem Homomorphieaxiom und →I/∀I; formal orientierte Kompositionsassoziativität; vollständige Konjunktionsschlüsse für beide Hilfssätze.
- Konjugation: h^{-1}=f folgt jetzt aus dem vorhandenen Satz über Eindeutigkeit der Umkehrfunktion mit Typisierung und Gleichheitssymmetrie.
- Die punktweisen Rechnungen für C_h(C_f(u))=u und C_f(C_h(w))=w geben alle benutzten Funktionstypen, die Mitgliedschaft der eingesetzten Werte, die einzelnen Konjugationsdefinitionen, den Satz über dreifache Kompositionsauswertung und die gerichteten =E-Schritte an. Danach folgen echte beschränkte ∀I und FunctionExtensionality.
- Beide Kompositionen C_h∘C_f und C_f∘C_h sind ausdrücklich als Selbstabbildungen typisiert; ebenso die jeweilige Identität. Punktweise Gleichheit, →I/∀I und FunctionExtensionality liefern die beiden Identitätsgleichungen vor dem Bijektivitätskriterium.
- Die Produktverträglichkeit der Konjugation besitzt jetzt zwei explizite, typisierte Auswertungsrechnungen mit Gleichheitselimination und anschließender Funktionsgleichheit. Der Rückschluss auf die Automorphismen-Bildmenge wurde mit einem konkreten Urbild, Bildzugehörigkeit, beschränkter Quantifizierung und Teilmengenantisymmetrie bewiesen.
- Unterstrukturordnungen: beide inversen Kompositionen sind typisiert und punktweise über die vorhandenen Umkehrbildsätze bewiesen. Die Vorwärtsmonotonie nimmt U⊆V ausdrücklich an und entlädt diese Annahme mit →I. Die Rückrichtung wendet Bildmonotonie auf h an und setzt die beiden bewiesenen Rückbildgleichungen ein.
- Kongruenzordnungen: zwei neue Hilfssätze beweisen Monotonie und Rücktransport des Relationsbildes mit expliziten Paarzeugen, ∃I*/∃E*, =E, ∀I und Teilmengensätzen. Die typisierten Kompositionsidentitäten und beide Monotonieimplikationen folgen anschließend mit echten Regelanwendungen.
- Termbasisfälle: Variable und Parameter werden jeweils über eine eigene Elementannahme behandelt; Definitionsgleichungen und =E liefern die exakte Matrix vor →I/∀I. Die früheren Gleichheits-/Mitgliedschaftsketten unter ∀ wurden beseitigt.
- Lösungsmengen: h∘(f∘α)=α und f∘(h∘β)=β sind durch einzelne Kompositionsauswertungen, richtige inverse Werte, beschränkte ∀I und FunctionExtensionality bewiesen. Die Rücktransportimplikation wird aus einer instanziierten Äquivalenz mit =E und ↔E gewonnen. Beide Kompositionen auf den Lösungsmengen werden vor dem Bijektivitätskriterium unabhängig und typisiert bewiesen.

## Neue Hilfsschlüssel

- `SemigroupTransportedRelationMonotonicity`: Monotonie des Relationsbildes (26 Schritte).
- `SemigroupTransportedCongruenceRoundTrip`: Rücktransport einer Kongruenz (50 Schritte).

## Validierung

- Alle 537 Beweisschritt-Makros parsebar; alle Abhängigkeitsindizes sind bereits eingeführte Annahmen; alle formalen numerischen Begründungsverweise zeigen rückwärts.
- Keine unersetzten symbolischen @-Schrittmarken.
- Alle 13 FunctionExtensionality-Anwendungen wurden mit den konkreten beiden Funktionstypen und der exakt passenden All-Matrix geprüft.
- Keine verbliebene Prosa „All-Einführung“, „Funktionsextensionalität“ oder „Implikationseinführung“ in den Begründungen dieser drei Familien.
- Die Gleichheitsrichtungen der neuen Rückkompositionen, Rückbilder, Paarzeugen und Monotonierückrichtungen wurden einzeln geprüft.
- Ausgangsstand: `b28-tail-before.tex`; pro Teilblock liegen eigene vorher/nachher-Dateien, Blockdiffs und Änderungsledger unter `b28-tail-*` vor. Maschinenlesbare Prüfung: `b28-tail-validation.json`.

## Getrennte fachliche Restlücken

1. `SemigroupTermEvaluationCarrier`, letzter Schritt (aktuell Quellzeile 3902): Die natürliche strukturelle Induktion über die endliche Termgrammatik bleibt als Schema beschrieben. Die Definition der Terme ist bislang eine Grammatik, kein formal konstruierter Termträger mit eingeführtem strukturellem Induktionssatz. Die Basisfälle sind jetzt vollständig formal; der abschließende Induktionsschluss darf ohne diese zusätzliche Konstruktion nicht durch ein erfundenes Regellabel ersetzt werden.
2. `SemigroupIsoTermEvaluation`, letzter Schritt (aktuell Quellzeile 3936): Dieselbe strukturelle Induktionslücke für die Verträglichkeit der Termauswertung. Die Basisfälle und vorhandenen algebraischen Schritte sind präzisiert; der allgemeine Induktionssatz über Terme fehlt weiterhin.
3. `SemigroupIsoEquationSolutionTransport`, Teil „Gleichheit, Systeme und Bijektivität“, Schritt16 (aktuell Quellzeile3954): Der Übergang von der Äquivalenz einer einzelnen Termgleichung zu einem beliebigen Gleichungssystem E und seiner Bildmenge E^f wird noch als Definitionseinsetzung über alle Paare beschrieben. Für eine durchgehend formale Fassung fehlen die formal typisierten Termpaarträger sowie die explizite Vorwärts-/Rückwärtsquantifizierung einschließlich Bildpaarzeugen. Die anschließenden quantifizierten Rückkompositionen und die Bijektivität sind nun unabhängig davon vollständig als Schlüsse aus dieser Äquivalenz ausgearbeitet.

Andere verbliebene Textbegründungen sind ausdrücklich lokale Definitionsentfaltungen (C_f/C_h, Φ/Ψ, Θ/Λ, Lösungsmengenzugehörigkeit) mit im Text angegebenen Wertzuordnungen. Sie ersetzen keine All-Einführung oder Funktionsgleichheitsregel. Das vollständige Restinventar steht in `b28-tail-remaining-reasons.json`.

## Teilinventar

| Teilbeweis | Schritte | Quellzeile beim Review |
| --- | ---: | ---: |
| Die beiden Kompositionshalbgruppen | 34 | 3351 |
| Abschluss und Träger der Konjugation | 33 | 3388 |
| Inverse Konjugation und Produkt | 137 | 3425 |
| Unterhalbgruppen und Ideale | 73 | 3610 |
| Monotonie des Relationsbildes | 26 | 3685 |
| Rücktransport einer Kongruenz | 50 | 3715 |
| Kongruenzen | 61 | 3769 |
| Auswertungen liegen im Träger | 15 | 3885 |
| Strukturelle Induktion über einen Term | 30 | 3904 |
| Gleichheit, Systeme und Bijektivität | 78 | 3938 |

## Abschließender Verschachtelungsnachtrag

Die zunächst verschachtelte Theoremreferenz der Kompositionsassoziativität wurde in eine eigene Zeile ausgezogen; danach folgt die Symmetrie in einer zweiten Zeile. Die Folgeschritte wurden mit edit_rows.py remappt. Teilbeweis Die beiden Kompositionshalbgruppen: 33 → 34 Schritte, gesamte Teilaufgabe: 536 → 537 Schritte. Ledger und Diff: b28-tail-associativity-lift-*.
