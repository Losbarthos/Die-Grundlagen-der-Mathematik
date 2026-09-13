# Abschließender unabhängiger Review der acht B08-Korrekturen

**Alle acht beauftragten Bereiche bestanden.** Geprüft wurde der von Agent01 freigegebene Quellenstand einschließlich des zusätzlichen Gleichheitsschritts bei `FixedEmptyBijectionNonemptyPreimageForward`. Keine weiteren Quellenänderungen oder Builds durch diesen Review.

| Bereich | Umfang | Ergebnis |
| --- | ---: | --- |
| 8.2.1.8, eindeutige Urbildexistenz | 15 Zeilen | Surjektive Existenzmatrix und injektiver Funktionstyp folgen ausdrücklich aus der Bijektivität. Die beiden Urbildannahmen werden durch `UEI{4,6,7,14}` korrekt entladen. Die Matrix entspricht der in Band 1 definierten beschränkten eindeutigen Existenz. |
| 8.2.2.1(H2), Zielmenge liegt im Bild | 16 Zeilen | Surjektivität und Funktionstyp sind als Belege vorhanden; der Urbildzeuge wird durch Existenzelimination entladen. Die Mitgliedsannahme wird vor der Allquantoreinführung entladen. |
| 8.3.1.4, umgekehrte Identitätsgleichung | 3 Zeilen | Beide Theoremaufrufe besitzen jetzt ihre konkreten Belegzeilen; Gleichheitssymmetrie richtig instanziiert. |
| 8.3.1.7, Bijektivität der Identität | 18 Zeilen | Die Gleichheitsannahme sowie beide Mitgliedsannahmen werden getrennt entladen. Surjektivität besitzt einen ausdrücklichen Zeugen und eine eigene Allquantoreinführung. Der Funktionstyp liegt vor. |
| 8.3.2.1, Einschränkung auf ein Urbild | 7 Zeilen | Injektivität und Surjektivität werden aus derselben Bijektivitätsannahme gewonnen und mit den passenden typisierten Einschränkungssätzen verwendet. Der letzte Schritt nutzt ausdrücklich den Satz „injektiv und surjektiv ergibt bijektiv“. |
| 8.3.2.2(H1), Bildrichtung der Einschränkung | 11 Zeilen | Der Funktionstyp von F wird vor dem Aufruf der Einschränkungsdefinition abgeleitet. Die beschränkte Wertgleichung wird mit der tatsächlichen Mitgliedschaft spezialisiert. Die Gleichheitsersetzung hat die richtige Richtung. |
| LayerPowerMapPreservesSubsetsBackward | 23 lokale Zeilen | Schritt 22 verwendet die beiden Gleichungen in der Reihenfolge 16,21 und liefert nun `LayerPowerMap(X)=X`. Damit kann Schritt 23 das Bild in der Teilmengenaussage aus Schritt 7 durch X ersetzen. |
| FixedEmptyBijectionNonemptyPreimageForward | 16 lokale Zeilen | Schritt 12 symmetrisiert zunächst Schritt 11 von `X=∅` zu `∅=X`; erst danach wird in `F(∅)=∅` gezielt das Funktionsargument ersetzt. Abhängigkeiten bleiben 2 und 11; der Widerspruchsschluss und die Entladung bleiben korrekt. |

Der unabhängige Strukturcheck berechnet die Abhängigkeiten aller **109 lokalen Beweiszeilen** erneut, einschließlich Existenz-, Eindeutigkeits-, Implikations- und Negationseinführung. Es bestehen keine Abweichungen zu den angegebenen Abhängigkeiten und keine ungültigen numerischen Schrittzugriffe. Die Gleichheitsrichtungen, Eigenvariablen und mathematischen Prämissen wurden zusätzlich inhaltlich kontrolliert.

Die acht Bereiche sind ausdrücklich begrenzt; dies ist keine neue umfassende Formalisierung aller älteren Regeln des Bandes. Das ausführliche Zeileninventar mit Einzelhashes steht in `final-fixes-independent-review.json`; reproduzierbarer Quellcheck: `review-final-fixes-independent.py`.

Nachtrag nach dem ersten B08-Build: In 8.2.1.8 wurde der Selektor des Injektivitätsaxioms zentral von `[thm]` zu `[ax]` berichtigt. Formel und Belegargumente blieben gleich. Der ursprüngliche Schlüsselcheck berücksichtigte die Registerart noch nicht; nun wurden die Inventare und Hashes aktualisiert und alle 200 Aufrufe der drei Reviewbereiche zusätzlich einschließlich Selektor geprüft. Keine Abweichung verbleibt; Beleg: `selector-aware-independent-review.json`.
