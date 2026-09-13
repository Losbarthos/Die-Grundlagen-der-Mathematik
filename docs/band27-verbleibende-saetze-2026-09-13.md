# Zweite Strukturprüfung des verbliebenen Bandes 27

Stand: 13. September 2026. Nur Quellenlektüre und diese Prüfnotiz; keine Manuskriptänderungen und kein Build. Nummern und Titel stammen aus der aktuellen `registry/_B27.registry.tsv`.

## Ergebnis

**Kein zusätzlicher unverändert formulierter allgemeiner Hauptsatz wurde gefunden, der unabhängig von den Wort- oder Baumdefinitionen nach Band 1–26 gehört.** Die erste Auslagerungsrunde wird hier nicht erneut gezählt. Das Ergebnis bedeutet nicht, dass jeder verbliebene Beweis schon die kürzeste Fassung hat: Zwei konkrete Wiederverwendungen früherer Sätze sind unten bestätigt. Ein zusätzlicher allgemeiner Satz über eine gemeinsame Stufe wachsender Mengenfolgen wäre fachlich sinnvoll, müsste aber erst als allgemeiner Satz formuliert werden.

Die Prüfung berücksichtigt die Hauptquelle und sämtliche aktiven Includes einschließlich Kapitel 6. Aussagen und lokale Parameter-/Prädikatsabkürzungen wurden berücksichtigt: Ein äußerlich allgemeines `C(H)` ist beispielsweise fest als Wort- oder Baumabschluss definiert. Die inventarisierende Prüfung ersetzt keine erneute vollständige Prüfung sämtlicher Ableitungszeilen.

## Grenzfälle: weshalb sie im Band bleiben

| Aktuelle Nummer / ID | Ort | Inhalt und Bewertung |
| --- | --- | --- |
| 27.2.1.1–3 / `FiniteOccurrenceSetUniverseMembership`, `FiniteOccurrenceUniverseEmpty`, `FiniteOccurrenceUniverseClosed` | `tex/b27-word-generated-set.tex`:32,74,87 | Elementkriterium, leere Menge und Abschluss von E_A = FinSubsets(N×A) unter J(w,a)=w∪{(#w,a)}. Die allgemeinen Mengen-/Endlichkeitssätze sind schon früher verfügbar; hier wird ausdrücklich das gewünschte Wortmodell eingeführt. E_A und J nach Band 20 zu verlagern verschöbe den Einstieg des Wortbandes, ohne eine neue allgemeine Theorie zu gewinnen. |
| 27.2.2.1–6 / Charakterisierung durch endliche Folgengraphen | `tex/b27-word-characterization.tex`, Haupttext vor Abschnitt Wortlänge | Die endlichen Graphsätze sind bereits ausgelagert. Die verbleibenden Aussagen identifizieren genau die erzeugte Wortmenge mit Folgengraphen. Die lokalen P-/Q-Induktionsblöcke enthalten dieselbe Wortmengenvoraussetzung und sind keine zusätzlichen allgemeinen Induktionssätze. |
| 27.2.6.3 / `WordStructurePairInjective` | `tex/b27-word-structure-consequences.tex`:21 | „Injektivität auf geordneten Paaren“ setzt WortStr_A(W,e,s) und speziell W2 voraus. Projektion und Paarrekonstruktion sind allgemeine Werkzeuge aus früheren Bänden; die Aussage selbst ist eine Wortaxiomen-Anwendung. |
| 27.2.6.7–12 / `WordRecursionFamilyMembership` bis `WordStructureRecursionLeastGraph` | `tex/b27-word-axiomatic-recursion.tex`:31–101 | Die Familie und ihr kleinster Graph sind durch C(H) definiert, wobei C die Basis (e,x0) und den Wortschritt (u,x)→(s(u,a),r(x,a)) verlangt. Die kurzen Aussonderungs-/Konjunktionsfolgen sind Anwendungen bereits vorhandener Logik- und Mengensätze. Der Existenzbeweis betrifft diese konkrete rekursive Abschlussbedingung. |
| 27.2.7.6 / `WordConcatenationIndexBlocksDisjoint` | Haupttext:705 | Aussage über die Längen zweier Wörter. Der allgemeine arithmetische Kern wird bereits durch `PeanoTailAvoidsInitialSegmentLeft` aus Band 10 angewandt. Keine weitere Auslagerung. |
| 27.2.7.7–8 / `WordConcatenationInitialGraphSubset`, `WordConcatenationShiftedGraphSubset` | Haupttext:728,763 | Typisierung der beiden konkreten Konkatenationsblöcke. Allgemeine Graph-, Produkt- und Termbildregeln sind schon früher verfügbar. Hier liegt ein lokaler Kürzungsfall vor, siehe unten. |
| 27.3.2.7–11 / Stufenmonotonie, Verschachtelung und `TreeCommonStage` | Haupttext:2884–3055 | Die allgemeinen Verschachtelungssätze für Mengenfolgen stehen bereits in Band 21. Die Aussagen über TreeStage_A sind Anwendungen; die gemeinsame Stufe ist der stärkste verbleibende Kandidat für eine optionale neue allgemeine Formulierung, nicht für unverändertes Verschieben. |
| 27.3.3.4 / `TreeCodeLeafInjectivity` | `tex/b27-tree-early-foundations.tex`:118 | Injektivität des konkret codierten Blattkonstruktors λ_A. Gehört zum Nachweis des Baummodells. |
| 27.3.4.7–12 / Träger, Abschluss, Minimalität und Faserwert eines Baumgraphen | `tex/b27-tree-axiomatic-recursion.tex`:35–271 | C(H) ist BCl_A(H;T,ℓ,k;X,f,g), M(G) ist diese Abschlussbedingung plus Minimalität. Die Aussagen sind trotz kurzer Schreibweise baumbezogen. Der allgemeine Faserfilter steht bereits in Band 7; bei 27.3.4.12 lässt sich seine stärkere Folgerung unmittelbar wiederverwenden. |
| 27.4.1.1 / `BinaryAddressPrefixSeparation` | Haupttext:3401 | Präfixabbildungen auf binären Wortadressen werden als disjunkt und injektiv nachgewiesen. Keine allgemeine Aussage über beliebige Bildmengen. |
| 27.4.1.3 / `BinaryAddressGraftBinaryOperation` | Haupttext:3558 | Die konkrete Adresspfropfung Γ ist eine binäre Operation auf P(BinaryAddresses). Allgemeine Typisierungs- und Termbildsätze sind früher vorhanden. |
| Positionsrekursor-Identifikation / `TreePositionRecursorIdentification` (Teilbeweis) | `tex/b27-position-recursor-existence.tex`:21 | Das äußerlich allgemeine Φ(P) bezeichnet genau die Blatt-/Knotenregeln der Positionsabbildung; R ist der betreffende Baumrekursor. Keine allgemeine Eindeutigkeitsregel. |
| 27.4.1.11–34 und 27.4.2.1–2 / Adresswege, Positionsgraphen, Elternsystem-Anwendungen | `tex/b27-address-paths.tex`, `tex/b27-general-rooted-trees.tex` | Die allgemeinen Pfad-/Elternsystemergebnisse sind schon in Band 26. Die verbleibenden Aussagen prüfen GoodAddressSet, AddressEdges und die konkreten Positionsmengen. Insbesondere `B27ForwardAddressSymmetrization` (:32) und `B27AddressRankedParentSystem` (:53) sind gerade die gewollten Anwendungen. |
| Kapitel 5 / Blattwörter, Klammerungen, Auswertungen | Haupttext ab4763 und die Includes Konstruktion/Linksklammerung/Auswertung | Alle Aussagen verknüpfen konkrete Baumkonstruktoren, Wortoperationen, Blattwörter oder die zugehörigen Rekursoren. Die Gleichsetzungen mit früheren Folgenbegriffen machen diese Anwendungen nicht fachfremd. |
| 27.6.1.1–3 / allgemeine Form von Wort- und Baumstrukturen | `tex/b27-structural-axioms.tex` | Trotz Kapitelüberschrift sind dies Darstellung/Isomorphie der hier eingeführten Wort- bzw. Baumstrukturen und der Sonderfall des leeren Alphabets. Keine allgemeine Strukturtheorie mit unabhängiger Aussage; anschließender Haupttext enthält keine weiteren Sätze. |

## Bestätigte Kürzungen durch bereits verfügbare allgemeine Sätze

Diese Fälle zählen **nicht** als zusätzliche Auslagerungen und beruhen nicht allein auf der neuen Teilmengenregel.

| Stelle | Vorher → mögliche Fassung | Fachliche Prüfung |
| --- | --- | --- |
| 27.2.7.8 H2, `WordConcatenationShiftedGraphSubsetPart`, Haupttext ab820 | **10 → 5 Beweiszeilen** | 1: u,v∈A*. 2: lokales j∈N_<|v|. 3: (|u|+j,v(j))∈N_<(|u|+|v|)×A durch H1 mit1,2. 4: beschränkte Allaussage durch ∀I/→I über2–3. 5: Termbild-Teilmengenbehauptung durch `B27TermImageSubset` (3.18.1.5) mit4. Die allgemeine Regel hat keine weitere Voraussetzung; auch der leere Indexbereich ist abgedeckt. |
| 27.3.4.12, `BinaryTreeRecursionFilteredFiberUnique`, `tex/b27-tree-axiomatic-recursion.tex`:271 | **17 → 14 Beweiszeilen** | Alte Zeilen9–12 (Filterelementkriterium, Disjunktion, Reflexivität, Disjunktionsschluss) lassen sich durch `WordRecursionFilterOwnFiber{5,8}` ersetzen. Mit U=T,V=X,K=G liefert die schon vorhandene Signatur aus G⊆T×X und (t,z)∈Φ^{T,X}_{t,c}(G) unmittelbar z=c. Kein zusätzlicher Typnachweis nötig; alle späteren Zeilen müssten beim tatsächlichen Edit korrekt umnummeriert werden. |

## Optionale neue Verallgemeinerungen, ausdrücklich keine bereits allgemeinen Sätze

1. **Gemeinsame Stufe einer wachsenden Mengenfolge.** Ausgangspunkt 27.3.2.11 „Gemeinsame Baumstufe“, `TreeCommonStage`, Haupttext:3055. Sinnvoller Zielort: Band 21, Abschnitt „Wachsende Folgen von Mengen“, direkt nach `SubsetSequenceNesting` (21.4.3.2; der Abschnitt beginnt in der B21-Hauptquelle:1123). Allgemeine Voraussetzungen wären D:N→P(M), ∀j∈N D(j)⊆D(j+1), ∃m∈N x∈D(m) und ∃n∈N y∈D(n); Schluss ∃q∈N x,y∈D(q). Benötigt ausschließlich Mengenmitgliedschaft, Vergleich natürlicher Zahlen (`PeanoOrderComparison`) und `SubsetSequenceNesting`. Keine Wörter/Bäume nötig. Der jetzige Satz könnte dann als kurze Baum-Anwendung bleiben. Das ist die sachlich überzeugendste optionale Ergänzung; ohne weitere Anwendungen rechtfertigt sie nicht von selbst einen erneuten größeren Umbau.

2. **Allgemeine Erzeugung durch Abschluss/kleinste abgeschlossene Menge.** Die Worterzeugung, der Wortrekursionsgraph und der Baumrekursionsgraph teilen einen Mengenschnittgedanken. Ein sauber formulierter allgemeiner Satz über den Schnitt einer Familie abgeschlossener Teilmengen könnte in Band 3 (nach Potenzmenge, Aussonderung und Schnitt) oder, bei funktionaler Formulierung der Operationen, in Band 5/7 stehen. Dafür müssen jedoch die Voraussetzungen „Umgebungsmenge ist abgeschlossen“ und „beliebige nichtleere Schnitte abgeschlossener Mengen sind abgeschlossen“ oder konkrete operationsbezogene Bedingungen ausdrücklich neu formuliert und bewiesen werden. Die aktuellen C-Prädikate lassen sich nicht ohne Änderung ihrer Aussage als bereits allgemeine Sätze dorthin verschieben. Empfehlung: erst bei Bedarf einer breiteren Theorie erzeugter Strukturen.

3. **Komponentenweise Injektivität versus Injektivität auf einem Produkt.** 27.2.6.3 könnte eine allgemeine Produktabbildungsregel in Band 7 motivieren, nach Projektionen und Paarrekonstruktion. Das wäre ein neuer Satz mit einer allgemeinen Injektivitätsannahme an s; die jetzige Aussage setzt ausdrücklich WortStr voraus. Der Nutzen für diese einzelne zwölfzeilige Anwendung ist gering. Keine Empfehlung für eine eigene Auslagerungsrunde.

4. **Allgemeines Minimalitäts-/Filterkriterium für eindeutige Fasern.** 27.3.4.12 könnte mit abstraktem C und expliziten Träger-/Minimalitätsannahmen zu einer allgemeinen Aussage werden. Gerade der allgemeine Filterkern liegt aber schon in Band 7; die bestätigte direkte Wiederverwendung oben liefert den Gewinn ohne neue Begriffsbildung. Daher keine zusätzliche Verallgemeinerung empfohlen.

## Vollständige Deckung der aktuellen Hauptsätze

Die nachstehende Liste erfasst jede aktuelle `FormulaThmDeltaK`-Deklaration genau einmal mit dem Registry-Titel. „Bleibt“ bedeutet: Die aktuelle Aussage ist wort-/baumbezogen. „Optional“ und „Kürzung“ verweisen auf die getrennten Bewertungen oben und bezeichnen keine unverändert verlagerbare Aussage. Definitionen, Axiome und die expliziten Induktions-/Teilbeweisblöcke wurden zusätzlich anhand ihrer Bedeutung und Abkürzungen geprüft; sie werden nicht als weitere Hauptsätze doppelt gezählt.

Erfasster Umfang: **40 aktive Quelldateien**, **233 Hauptsätze**, **114 ausdrücklich formulierte Induktions-/Teilbeweisblöcke**.

| Nummer | Exakter Titel | ID | Quelle:Zeile | Bewertung |
| --- | --- | --- | --- | --- |
| 27.2.1.1 | Elemente des Umgebungsbereichs | `FiniteOccurrenceSetUniverseMembership` | `tex/b27-word-generated-set.tex`:32 | Bleibt |
| 27.2.1.2 | Die leere Menge liegt im Umgebungsbereich | `FiniteOccurrenceUniverseEmpty` | `tex/b27-word-generated-set.tex`:74 | Bleibt |
| 27.2.1.3 | Der Erzeugungsschritt bleibt im Umgebungsbereich | `FiniteOccurrenceUniverseClosed` | `tex/b27-word-generated-set.tex`:87 | Bleibt |
| 27.2.1.4 | Elementkriterium der abgeschlossenen Mengen | `WordGenerationFamilyMembership` | `tex/b27-word-generated-set.tex`:133 | Bleibt |
| 27.2.1.5 | Der Umgebungsbereich ist eine abgeschlossene Menge | `WordGenerationUniverseMember` | `tex/b27-word-generated-set.tex`:182 | Bleibt |
| 27.2.1.6 | Die Familie abgeschlossener Mengen ist nicht leer | `WordGenerationFamilyNonempty` | `tex/b27-word-generated-set.tex`:201 | Bleibt |
| 27.2.1.7 | Elementkriterium des erzeugten Wortbereichs | `GeneratedWordMembership` | `tex/b27-word-generated-set.tex`:228 | Bleibt |
| 27.2.1.8 | Jede abgeschlossene Menge enthält alle Wörter | `FiniteWordSetGenerationLeast` | `tex/b27-word-generated-set.tex`:249 | Bleibt |
| 27.2.1.9 | Die Wortmenge liegt im Umgebungsbereich | `FiniteWordSetSubsetUniverse` | `tex/b27-word-generated-set.tex`:265 | Bleibt |
| 27.2.1.10 | Jedes Wort liegt im Umgebungsbereich | `FiniteWordInUniverse` | `tex/b27-word-generated-set.tex`:276 | Bleibt |
| 27.2.1.11 | Jedes Wort ist eine endliche Menge | `FiniteWordUnderlyingFinite` | `tex/b27-word-generated-set.tex`:288 | Bleibt |
| 27.2.1.12 | Das leere Wort | `GeneratedWordEmpty` | `tex/b27-word-generated-set.tex`:300 | Bleibt |
| 27.2.1.13 | Wörter bleiben unter dem Erzeugungsschritt abgeschlossen | `GeneratedWordClosed` | `tex/b27-word-generated-set.tex`:318 | Bleibt |
| 27.2.1.14 | Die Wortmenge ist eine abgeschlossene Menge | `FiniteWordSetGenerationClosed` | `tex/b27-word-generated-set.tex`:345 | Bleibt |
| 27.2.1.15 | Minimalität der erzeugten Wortmenge | `GeneratedWordMinimality` | `tex/b27-word-generated-set.tex`:361 | Bleibt |
| 27.2.1.16 | Induktion für erzeugte Wörter | `GeneratedWordInduction` | `tex/b27-word-generated-set.tex`:386 | Bleibt |
| 27.2.1.17 | Induktionsregel für erzeugte Wörter | `GeneratedWordInductionRule` | `tex/b27-word-generated-set.tex`:437 | Bleibt |
| 27.2.2.1 | Die Erzeugungsregeln liefern lückenlose Funktionsgraphen | `GeneratedWordGraphTyping` | `tex/b27-word-characterization.tex`:13 | Bleibt |
| 27.2.2.2 | Jede endliche Folge wird durch die Wortregeln erzeugt | `B27FiniteGraphGenerated` | `tex/b27-word-characterization.tex`:68 | Bleibt |
| 27.2.2.3 | Funktionenkriterium der endlichen Wortmenge | `FiniteWordSetMembership` | `tex/b27-word-characterization.tex`:128 | Bleibt |
| 27.2.2.4 | Einführung eines endlichen Wortes | `FiniteWordSetIntroduction` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:194 | Bleibt |
| 27.2.2.5 | Typisierte endliche Folgen sind endliche Wörter | `FiniteWordFromTyping` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:210 | Bleibt |
| 27.2.2.6 | Eindeutige Länge eines endlichen Wortes | `FiniteWordLengthUnique` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:223 | Bleibt |
| 27.2.3.1 | Wortlänge ist die Kardinalzahl der aufgebauten Menge | `FiniteWordLengthCardinality` | `tex/b27-word-length.tex`:15 | Bleibt |
| 27.2.3.2 | Typisierung durch die Wortlänge | `FiniteWordTyping` | `tex/b27-word-length.tex`:28 | Bleibt |
| 27.2.3.3 | Länge aus einer gegebenen Worttypisierung | `FiniteWordLengthFromTyping` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:281 | Bleibt |
| 27.2.4.1 | Typisierung des Leerwortes | `EmptyWordTyping` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:313 | Bleibt |
| 27.2.4.2 | Das Leerwort hat Länge null | `EmptyWordLength` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:330 | Bleibt |
| 27.2.4.3 | Länge null kennzeichnet das Leerwort | `FiniteWordLengthZeroIffEmpty` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:365 | Bleibt |
| 27.2.4.4 | Nichtleeres Wort und von null verschiedene Länge | `FiniteWordLengthNonzeroIffNonempty` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:403 | Bleibt |
| 27.2.4.5 | Elementkriterium für nichtleere Wörter | `NonemptyWordMembership` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:433 | Bleibt |
| 27.2.4.6 | Typisierung nichtleerer Wörter | `NonemptyWordTyping` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:480 | Bleibt |
| 27.2.4.7 | Grundgesetze der Buchstabenwörter | `LetterWordFacts` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:547 | Bleibt |
| 27.2.5.1 | Die primitive Anfügung bleibt in der Wortmenge | `EarlyWordAdjunctionClosed` | `tex/b27-word-early-core.tex`:16 | Bleibt |
| 27.2.5.2 | W0: Typisierung des konkreten Wortmodells | `EarlyWordSuccessorTyping` | `tex/b27-word-early-core.tex`:48 | Bleibt |
| 27.2.5.3 | Grundgleichung der primitiven Anfügung | `EarlyWordSuccessorEquation` | `tex/b27-word-early-core.tex`:71 | Bleibt |
| 27.2.5.4 | Die Anfügungsfunktion führt die Erzeugungsregel aus | `EarlyWordSuccessorGenerationEquation` | `tex/b27-word-early-core.tex`:98 | Bleibt |
| 27.2.5.5 | Wortzugehörigkeit und Länge eines primitiven Nachfolgers | `EarlyWordSuccessorLength` | `tex/b27-word-early-core.tex`:115 | Bleibt |
| 27.2.5.6 | W1: Das Leerwort ist kein primitiver Nachfolger | `EarlyWordSuccessorNonempty` | `tex/b27-word-early-core.tex`:138 | Bleibt |
| 27.2.5.7 | Werte vor und an der neuen letzten Position | `EarlyWordSuccessorValues` | `tex/b27-word-early-core.tex`:154 | Bleibt |
| 27.2.5.8 | W2: Gemeinsame Injektivität der primitiven Anfügung | `EarlyWordSuccessorInjective` | `tex/b27-word-early-core.tex`:184 | Bleibt |
| 27.2.5.9 | W3: Minimalität des konkreten Wortmodells | `EarlyWordModelMinimality` | `tex/b27-word-early-minimality.tex`:10 | Bleibt |
| 27.2.6.1 | Existenz einer freien Wortstruktur | `WordStructureConcreteModel` | `tex/b27-word-concrete-model.tex`:1 | Bleibt |
| 27.2.6.2 | Typisierung eines Anfügungsschritts | `WordStructureStepTyping` | `tex/b27-word-structure-consequences.tex`:6 | Bleibt |
| 27.2.6.3 | Injektivität auf geordneten Paaren | `WordStructurePairInjective` | `tex/b27-word-structure-consequences.tex`:21 | Bleibt; optionale Verallgemeinerung |
| 27.2.6.4 | Induktion in einer Wortstruktur | `WordStructureInduction` | `tex/b27-word-structure-consequences.tex`:45 | Bleibt |
| 27.2.6.5 | Induktionsregel in einer Wortstruktur | `WordStructureInductionRule` | `tex/b27-word-structure-consequences.tex`:77 | Bleibt |
| 27.2.6.6 | Eindeutige Endzerlegung in einer Wortstruktur | `WordStructureDecomposition` | `tex/b27-word-structure-consequences.tex`:116 | Bleibt |
| 27.2.6.7 | Mitgliedschaft in der Familie abgeschlossener Graphen | `WordRecursionFamilyMembership` | `tex/b27-word-axiomatic-recursion.tex`:31 | Bleibt |
| 27.2.6.8 | Elementkriterium des kleinsten Rekursionsgraphen | `WordRecursionLeastMembership` | `tex/b27-word-axiomatic-recursion.tex`:49 | Bleibt |
| 27.2.6.9 | Trägermenge eines abgeschlossenen Graphen | `WordRecursionClosedGraphSubset` | `tex/b27-word-axiomatic-recursion.tex`:60 | Bleibt |
| 27.2.6.10 | Anfangspunkt eines abgeschlossenen Graphen | `WordRecursionClosedGraphBase` | `tex/b27-word-axiomatic-recursion.tex`:72 | Bleibt |
| 27.2.6.11 | Einzelner Schritt in einem abgeschlossenen Graphen | `WordRecursionClosedGraphStep` | `tex/b27-word-axiomatic-recursion.tex`:84 | Bleibt |
| 27.2.6.12 | Kleinster abgeschlossener Rekursionsgraph | `WordStructureRecursionLeastGraph` | `tex/b27-word-axiomatic-recursion.tex`:101 | Bleibt; optionale Verallgemeinerung |
| 27.2.6.13 | Eindeutiger Anfangswert des kleinsten Graphen | `WordStructureRecursionBaseFiber` | `tex/b27-word-axiomatic-recursion.tex`:146 | Bleibt |
| 27.2.6.14 | Eindeutige Werte bleiben beim Anfügen eindeutig | `WordStructureRecursionStepFiber` | `tex/b27-word-axiomatic-recursion.tex`:188 | Bleibt |
| 27.2.6.15 | Der kleinste Rekursionsgraph ist eine Funktion | `WordStructureRecursionGraphFunction` | `tex/b27-word-axiomatic-recursion.tex`:240 | Bleibt |
| 27.2.6.16 | Rekursionsgleichungen des kleinsten Graphen | `WordStructureRecursionGraphEquations` | `tex/b27-word-axiomatic-recursion.tex`:262 | Bleibt |
| 27.2.6.17 | Eindeutigkeit der Wortrekursion | `WordStructureRecursionUniqueness` | `tex/b27-word-axiomatic-recursion.tex`:292 | Bleibt |
| 27.2.6.18 | Rekursion in jeder freien Wortstruktur | `WordStructureRecursion` | `tex/b27-word-axiomatic-recursion.tex`:324 | Bleibt |
| 27.2.6.19 | Rekursion vom Leerwort aus | `FiniteWordRecursion` | `tex/b27-word-axiomatic-recursion.tex`:343 | Bleibt |
| 27.2.6.20 | Zwei Lösungen derselben Wortrekursion sind gleich | `WordRecursionTwoSolutionsEqual` | `tex/b27-word-canonical-isomorphism.tex`:6 | Bleibt |
| 27.2.6.21 | Die Identität erfüllt die Wortrekursion | `WordRecursionIdentity` | `tex/b27-word-canonical-isomorphism.tex`:22 | Bleibt |
| 27.2.6.22 | Komposition von Rekursionsabbildungen | `WordRecursionComposition` | `tex/b27-word-canonical-isomorphism.tex`:43 | Bleibt |
| 27.2.6.23 | Rekursionsabbildungen zwischen Wortstrukturen sind Isomorphismen | `WordStructureRecursorIsomorphism` | `tex/b27-word-canonical-isomorphism.tex`:73 | Bleibt |
| 27.2.6.24 | Kanonische Darstellung jeder Wortstruktur | `WordStructureCanonicalIsomorphism` | `tex/b27-word-canonical-isomorphism.tex`:100 | Bleibt |
| 27.2.7.1 | Anfügung ist Adjunktion des letzten Vorkommens | `WordAppendOccurrenceEquation` | `tex/b27-word-concatenation-adjunction.tex`:8 | Bleibt |
| 27.2.7.2 | Das angefügte Vorkommen ist neu | `WordAppendOccurrenceFresh` | `tex/b27-word-concatenation-adjunction.tex`:37 | Bleibt |
| 27.2.7.3 | Endlichkeit der Anfügung aus dem Adjunktionsaxiom | `WordAppendFiniteByAdjunction` | `tex/b27-word-concatenation-adjunction.tex`:56 | Bleibt |
| 27.2.7.4 | Die primitive Anfügung ist Konkatenation mit einem Buchstabenwort | `WordModelSuccessorConcatenation` | `tex/b27-word-concatenation-adjunction.tex`:73 | Bleibt |
| 27.2.7.5 | Elementkriterium der Wortkonkatenation | `WordConcatenationMembership` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:646 | Bleibt |
| 27.2.7.6 | Disjunktheit der Indexblöcke einer Konkatenation | `WordConcatenationIndexBlocksDisjoint` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:705 | Bleibt |
| 27.2.7.7 | Typisierung des Anfangsblocks einer Konkatenation | `WordConcatenationInitialGraphSubset` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:728 | Bleibt |
| 27.2.7.8 | Typisierung des verschobenen Konkatenationsblocks | `WordConcatenationShiftedGraphSubset` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:763 | Bleibt; lokale Kürzung |
| 27.2.7.9 | Totalität des Konkatenationsgraphen | `WordConcatenationGraphTotal` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:846 | Bleibt |
| 27.2.7.10 | Funktionalität des Konkatenationsgraphen | `WordConcatenationGraphFunctional` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:948 | Bleibt |
| 27.2.7.11 | Typisierung und Koordinaten der Konkatenation | `WordConcatenationTyping` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1135 | Bleibt |
| 27.2.7.12 | Abgeschlossenheit der endlichen Wortmenge unter Konkatenation | `WordConcatenationClosure` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1287 | Bleibt |
| 27.2.7.13 | Länge einer Konkatenation | `WordConcatenationLength` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1307 | Bleibt |
| 27.2.7.14 | Kürzung bei festem Konkatenationsschnitt | `WordConcatenationFixedCutCancellation` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1337 | Bleibt |
| 27.2.7.15 | Leerwortgesetze der Konkatenation | `WordConcatenationIdentity` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1451 | Bleibt |
| 27.2.7.16 | Konkatenation verträgt die Anfügung rechts | `WordConcatenationSuccessor` | `tex/b27-word-concatenation-successor.tex`:7 | Bleibt |
| 27.2.7.17 | Assoziativität der Wortkonkatenation | `WordConcatenationAssociative` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1548 | Bleibt |
| 27.2.7.18 | Abgeschlossenheit nichtleerer Konkatenationen | `NonemptyWordConcatenationClosure` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1560 | Bleibt |
| 27.2.8.1 | Injektivität der Buchstabenwörter | `LetterWordInjectivity` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1591 | Bleibt |
| 27.2.8.2 | Wörter der Länge eins sind Buchstabenwörter | `FiniteWordLengthOneCharacterization` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1616 | Bleibt |
| 27.2.8.3 | Länge nach Anhängen eines Buchstabens | `WordAppendLetterLength` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1696 | Bleibt |
| 27.2.8.4 | Letzter Wert nach Anhängen eines Buchstabens | `WordAppendLetterLastCoordinate` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1720 | Bleibt |
| 27.2.8.5 | Eindeutige Rechtszerlegung eines Nichtleerwortes | `NonemptyWordRightDecomposition` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1755 | Bleibt |
| 27.2.8.6 | Typisierung der Rumpffunktion | `WordRumpfFunction` | `tex/b27-word-end-operations.tex`:46 | Bleibt |
| 27.2.8.7 | Der Rumpf ist ein endliches Wort | `WordRumpfTyping` | `tex/b27-word-end-operations.tex`:54 | Bleibt |
| 27.2.8.8 | Zum Rumpf gehört genau ein Endbuchstabe | `WordRumpfCharacterization` | `tex/b27-word-end-operations.tex`:65 | Bleibt |
| 27.2.8.9 | Typisierung der Endbuchstabenfunktion | `WordEndFunction` | `tex/b27-word-end-operations.tex`:116 | Bleibt |
| 27.2.8.10 | Der Endbuchstabe liegt im Alphabet | `WordEndTyping` | `tex/b27-word-end-operations.tex`:124 | Bleibt |
| 27.2.8.11 | Rumpf und Endbuchstabe setzen das Wort wieder zusammen | `WordRightDecompositionEquation` | `tex/b27-word-end-operations.tex`:135 | Bleibt |
| 27.2.8.12 | Eine gegebene Endzerlegung bestimmt Rumpf und Endbuchstabe | `WordRightDecompositionIdentification` | `tex/b27-word-end-operations.tex`:153 | Bleibt |
| 27.2.8.13 | Ein angehängter Buchstabe macht ein Wort nichtleer | `WordAppendNonempty` | `tex/b27-word-end-operations.tex`:209 | Bleibt |
| 27.2.8.14 | Anhängen und Entfernen eines Endbuchstabens | `WordRumpfAppend` | `tex/b27-word-end-operations.tex`:230 | Bleibt |
| 27.2.8.15 | Der angehängte Buchstabe ist der Endbuchstabe | `WordEndAppend` | `tex/b27-word-end-operations.tex`:246 | Bleibt |
| 27.2.8.16 | Der Rumpf ist um einen Buchstaben kürzer | `WordRumpfLength` | `tex/b27-word-end-operations.tex`:262 | Bleibt |
| 27.2.8.17 | Gleiche angehängte Wörter haben dieselben Bestandteile | `WordAppendJointInjectivity` | `tex/b27-word-end-operations.tex`:282 | Bleibt |
| 27.2.8.18 | Strukturinduktion über alle endlichen Wörter | `FiniteWordStructuralInduction` | `tex/b27-word-finite-induction.tex`:9 | Bleibt |
| 27.2.8.19 | Die Wortmenge ist die kleinste unter Anfügung abgeschlossene Menge | `FiniteWordSetLeastAppendClosed` | `tex/b27-word-finite-induction.tex`:26 | Bleibt |
| 27.2.8.20 | Induktion über nichtleere Wörter | `NonemptyWordInduction` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1774 | Bleibt |
| 27.2.8.21 | Rekursion über nichtleere Wörter | `NonemptyWordRecursion` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1789 | Bleibt |
| 27.2.9.1 | Existenz und Eindeutigkeit der Linksfaltung | `LeftWordFoldExistence` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1807 | Bleibt |
| 27.2.9.2 | Kennzeichnung der Linksfaltung | `LeftWordFoldCharacterization` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1925 | Bleibt |
| 27.2.9.3 | Typisierung der Linksfaltung | `LeftWordFoldFunction` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1999 | Bleibt |
| 27.2.9.4 | Rekursionsgleichungen der Linksfaltung | `LeftWordFoldEquations` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:2012 | Bleibt |
| 27.3.1.1 | Wohldefiniertheit der Knotencodedaten | `TreeNodeCodeTyping` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:2116 | Bleibt |
| 27.3.1.2 | Konstruktortrennung und -injektivität | `TreeConstructorNoConfusion` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:2285 | Bleibt |
| 27.3.2.1 | Der Erzeugungsschritt ist eine Abbildung | `TreeGenerationStepFunction` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:2541 | Bleibt |
| 27.3.2.2 | Monotonie des Erzeugungsschritts | `TreeGenerationStepMonotonicity` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:2630 | Bleibt |
| 27.3.2.3 | Typisierung der gesamten Baumstufenfolge | `TreeStageSequenceTyping` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:2753 | Bleibt |
| 27.3.2.4 | Nullgleichung der Baumstufen | `TreeStageZeroEquation` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:2776 | Bleibt |
| 27.3.2.5 | Nachfolgergleichung der Baumstufen | `TreeStageSuccessorEquation` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:2803 | Bleibt |
| 27.3.2.6 | Typisierung der Baumstufen | `TreeStageTyping` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:2833 | Bleibt |
| 27.3.2.7 | Monotonie der Baumstufen | `TreeStageMonotone` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:2884 | Bleibt |
| 27.3.2.8 | Additive Verschachtelung der Baumstufen | `TreeStageAdditiveNested` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:2965 | Bleibt |
| 27.3.2.9 | Verschachtelung der Baumstufen | `TreeStageNested` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:2996 | Bleibt |
| 27.3.2.10 | Jede Baumstufe liegt im Baumträger | `TreeStageSubsetTreeSet` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:3029 | Bleibt |
| 27.3.2.11 | Gemeinsame Baumstufe | `TreeCommonStage` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:3055 | Bleibt; optionale Verallgemeinerung |
| 27.3.2.12 | Konstruktorabschluss der Klammerungsbäume | `TreeConstructorClosure` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:3203 | Bleibt |
| 27.3.3.1 | Typisierung der konkreten Baumkonstruktoren (B0) | `TreeCodeConstructorTyping` | `tex/b27-tree-early-foundations.tex`:33 | Bleibt |
| 27.3.3.2 | Wert des konkreten Blattkonstruktors | `TreeCodeLeafValue` | `tex/b27-tree-early-foundations.tex`:64 | Bleibt |
| 27.3.3.3 | Wert des konkreten Knotenkonstruktors | `TreeCodeNodeValue` | `tex/b27-tree-early-foundations.tex`:85 | Bleibt |
| 27.3.3.4 | Blatteindeutigkeit des konkreten Modells (B1) | `TreeCodeLeafInjectivity` | `tex/b27-tree-early-foundations.tex`:118 | Bleibt |
| 27.3.3.5 | Knoteneindeutigkeit des konkreten Modells (B2) | `TreeCodeNodeInjectivity` | `tex/b27-tree-early-foundations.tex`:138 | Bleibt |
| 27.3.3.6 | Trennung der konkreten Konstruktoren (B3) | `TreeCodeConstructorSeparation` | `tex/b27-tree-early-foundations.tex`:167 | Bleibt |
| 27.3.3.7 | Abgeschlossene Teilmengen enthalten die nächste Baumstufe | `TreeCodeStageContainmentStep` | `tex/b27-tree-early-foundations.tex`:196 | Bleibt |
| 27.3.3.8 | Minimalität des konkreten Baumträgers (B4) | `TreeCodeMinimality` | `tex/b27-tree-early-foundations.tex`:283 | Bleibt |
| 27.3.4.1 | Existenz einer freien Klammerungsbaumstruktur | `BinaryTreeStructureConcreteModel` | `tex/b27-tree-early-axioms.tex`:145 | Bleibt |
| 27.3.4.2 | Blätter liegen im Strukturträger | `BinaryTreeStructureLeafTyping` | `tex/b27-tree-early-axioms.tex`:207 | Bleibt |
| 27.3.4.3 | Knoten liegen im Strukturträger | `BinaryTreeStructureNodeTyping` | `tex/b27-tree-early-axioms.tex`:224 | Bleibt |
| 27.3.4.4 | Eindeutigkeit des geordneten Kinderpaares | `BinaryTreeStructurePairInjective` | `tex/b27-tree-early-axioms.tex`:243 | Bleibt |
| 27.3.4.5 | Induktion in einer Baumstruktur | `BinaryTreeStructureInduction` | `tex/b27-tree-early-axioms.tex`:278 | Bleibt |
| 27.3.4.6 | Eindeutige Zerlegung in einer Baumstruktur | `BinaryTreeStructureDecomposition` | `tex/b27-tree-early-axioms.tex`:351 | Bleibt |
| 27.3.4.7 | Träger eines abgeschlossenen Baumgraphen | `BinaryTreeClosedGraphSubset` | `tex/b27-tree-axiomatic-recursion.tex`:35 | Bleibt |
| 27.3.4.8 | Blattregel eines abgeschlossenen Baumgraphen | `BinaryTreeClosedGraphLeaf` | `tex/b27-tree-axiomatic-recursion.tex`:52 | Bleibt |
| 27.3.4.9 | Knotenregel eines abgeschlossenen Baumgraphen | `BinaryTreeClosedGraphNode` | `tex/b27-tree-axiomatic-recursion.tex`:73 | Bleibt |
| 27.3.4.10 | Minimalität des abgeschlossenen Baumgraphen | `BinaryTreeMinimalGraphSubset` | `tex/b27-tree-axiomatic-recursion.tex`:100 | Bleibt |
| 27.3.4.11 | Existenz des kleinsten abgeschlossenen Baumgraphen | `BinaryTreeLeastClosedGraphExists` | `tex/b27-tree-axiomatic-recursion.tex`:122 | Bleibt |
| 27.3.4.12 | Ein zulässiger Faserfilter erzwingt einen einzigen Wert | `BinaryTreeRecursionFilteredFiberUnique` | `tex/b27-tree-axiomatic-recursion.tex`:271 | Bleibt; lokale Kürzung |
| 27.3.4.13 | Eindeutiger Wert am Blatt | `BinaryTreeRecursionLeafFiberUnique` | `tex/b27-tree-axiomatic-recursion.tex`:319 | Bleibt |
| 27.3.4.14 | Eindeutige Teilwerte bestimmen einen eindeutigen Knotenwert | `BinaryTreeRecursionNodeFiberUnique` | `tex/b27-tree-axiomatic-recursion.tex`:413 | Bleibt |
| 27.3.4.15 | Der kleinste Baumgraph ist eine Funktion | `BinaryTreeRecursionGraphFunction` | `tex/b27-tree-axiomatic-recursion.tex`:522 | Bleibt |
| 27.3.4.16 | Ein abgeschlossener Funktionsgraph erfüllt die Rekursionsgleichungen | `BinaryTreeRecursionGraphEquations` | `tex/b27-tree-axiomatic-recursion.tex`:566 | Bleibt |
| 27.3.4.17 | Zwei Lösungen derselben Baumrekursion stimmen überein | `BinaryTreeRecursionTwoSolutionsEqual` | `tex/b27-tree-axiomatic-recursion.tex`:614 | Bleibt |
| 27.3.4.18 | Rekursion in jeder freien Baumstruktur | `BinaryTreeStructureRecursion` | `tex/b27-tree-axiomatic-recursion.tex`:676 | Bleibt |
| 27.3.4.19 | Konstruktorzerlegung | `TreeConstructorDecomposition` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:3289 | Bleibt |
| 27.3.5.1 | Strukturinduktion auf Klammerungsbäumen | `FullPlanarBinaryTreeStructuralInduction` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:3313 | Bleibt |
| 27.3.5.2 | Strukturrekursion auf Klammerungsbäumen | `FullPlanarBinaryTreeRecursion` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:3330 | Bleibt |
| 27.3.5.3 | Die Identität erfüllt die Baumrekursionsgleichungen | `BinaryTreeRecursionIdentity` | `tex/b27-tree-canonical-isomorphism.tex`:9 | Bleibt |
| 27.3.5.4 | Komposition strukturtreuer Baumabbildungen | `BinaryTreeRecursionComposition` | `tex/b27-tree-canonical-isomorphism.tex`:50 | Bleibt |
| 27.3.5.5 | Strukturtreue Rekursoren zwischen freien Baumstrukturen sind bijektiv | `BinaryTreeStructureRecursorIsomorphism` | `tex/b27-tree-canonical-isomorphism.tex`:128 | Bleibt |
| 27.3.5.6 | Kanonische Darstellung jeder Baumstruktur | `BinaryTreeStructureCanonicalIsomorphism` | `tex/b27-tree-canonical-isomorphism.tex`:172 | Bleibt |
| 27.3.5.7 | Charakterisierung des Baumrekursors | `TreeRecursorSpecification` | `tex/b27-tree-recursor.tex`:29 | Bleibt |
| 27.3.5.8 | Typisierung, Blattregel und Knotenregel | `TreeRecursorEquations` | `tex/b27-tree-recursor.tex`:66 | Bleibt |
| 27.3.5.9 | Identifikationsregel für den Baumrekursor | `TreeRecursorIdentification` | `tex/b27-tree-recursor.tex`:169 | Bleibt |
| 27.3.5.10 | Baumrekursor mit binärer Operation | `TreeRecursorBinaryOperationEquations` | `tex/b27-tree-recursor.tex`:219 | Bleibt |
| 27.3.5.11 | Identifikation bei einer binären Operation | `TreeRecursorBinaryOperationIdentification` | `tex/b27-tree-recursor.tex`:304 | Bleibt |
| 27.4.1.1 | Trennung und Injektivität der Adresspräfixe | `BinaryAddressPrefixSeparation` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:3401 | Bleibt |
| 27.4.1.2 | Die beiden Adresskinder sind verschieden | `BinaryAddressChildrenDistinct` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:3511 | Bleibt |
| 27.4.1.3 | Die Adresspfropfung ist eine binäre Operation | `BinaryAddressGraftBinaryOperation` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:3558 | Bleibt |
| 27.4.1.4 | Kriterium für volle endliche Präfixmengen | `GoodBinaryAddressSetCriterion` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:3655 | Bleibt |
| 27.4.1.5 | Ein angehängtes Adressbit erzeugt nicht die Wurzel | `B27BinaryAppendNotRoot` | `tex/b27-graft-proof-lemmas.tex`:2 | Bleibt |
| 27.4.1.6 | Ein vorangestelltes Adressbit erzeugt nicht die Wurzel | `B27BinaryPrefixNotRoot` | `tex/b27-graft-proof-lemmas.tex`:16 | Bleibt |
| 27.4.1.7 | Die beiden Präfixbilder in einer Pfropfung | `B27GraftPrefixMembership` | `tex/b27-graft-proof-lemmas.tex`:38 | Bleibt |
| 27.4.1.8 | Präfixabschluss der gepfropften Adressmenge | `B27GraftPrefixClosure` | `tex/b27-graft-proof-lemmas.tex`:81 | Bleibt |
| 27.4.1.9 | Volle Verzweigung der gepfropften Adressmenge | `B27GraftFullness` | `tex/b27-graft-proof-lemmas.tex`:139 | Bleibt |
| 27.4.1.10 | Grund- und Pfropfschritt voller Präfixmengen | `GoodBinaryAddressSetConstructors` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:3726 | Bleibt |
| 27.4.1.11 | Existenz und Eindeutigkeit der Positionsabbildung | `TreePositionMapExistenceUnique` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:3936 | Bleibt |
| 27.4.1.12 | Rekursionsgleichungen der Positionsmenge | `TreePositionSetEquations` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:3964 | Bleibt |
| 27.4.1.13 | Positionsmengen sind volle endliche Präfixmengen | `TreePositionSetIsGood` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:4075 | Bleibt |
| 27.4.1.14 | Adressfortsetzungen bilden eine Paarmenge | `B27BinaryChildTermSetPair` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:4197 | Bleibt |
| 27.4.1.15 | Adresszugehörigkeit | `B27AddressWordTyping` | `tex/b27-address-paths.tex`:20 | Bleibt |
| 27.4.1.16 | Ein angehängter Buchstabe ergibt kein Leerwort | `B27WordAppendNotEmpty` | `tex/b27-address-paths.tex`:33 | Bleibt |
| 27.4.1.17 | Elementkriterium der Adresskanten | `B27AddressEdgeCriterion` | `tex/b27-address-paths.tex`:52 | Bleibt |
| 27.4.1.18 | Ein einfacher Adresspfad kehrt nicht sofort um | `B27AddressNoImmediateReturn` | `tex/b27-address-paths.tex`:89 | Bleibt |
| 27.4.1.19 | Adressfortsetzung ist eine Kante | `B27AddressAppendEdge` | `tex/b27-address-paths.tex`:131 | Bleibt |
| 27.4.1.20 | Der Rumpf bleibt in der Präfixmenge | `B27AddressRumpfClosure` | `tex/b27-address-paths.tex`:161 | Bleibt |
| 27.4.1.21 | Die beiden Richtungen einer Adresskante | `B27AddressEdgeDirections` | `tex/b27-address-paths.tex`:189 | Bleibt |
| 27.4.1.22 | Eine Adresskante aus der Wurzel führt vorwärts | `B27AddressRootEdgeForward` | `tex/b27-address-paths.tex`:215 | Bleibt |
| 27.4.1.23 | Jede Adresse besitzt einen Wurzelpfad | `B27AddressRootPathExists` | `tex/b27-address-paths.tex`:251 | Bleibt |
| 27.4.1.24 | Jeder Wurzelpfadschritt fügt ein Bit an | `B27AddressRootPathForward` | `tex/b27-address-paths.tex`:330 | Bleibt |
| 27.4.1.25 | Die Adresslänge zählt die Pfadschritte | `B27AddressRootPathRanks` | `tex/b27-address-paths.tex`:422 | Bleibt |
| 27.4.1.26 | Der vorherige Pfadknoten ist der Rumpf | `B27AddressRootPathRumpf` | `tex/b27-address-paths.tex`:502 | Bleibt |
| 27.4.1.27 | Wurzelpfade mit gleichem Endknoten stimmen überein | `B27AddressRootPathEquality` | `tex/b27-address-paths.tex`:532 | Bleibt |
| 27.4.1.28 | Eindeutigkeit gespeicherter Wurzelpfade | `B27AddressStoredRootPathsEqual` | `tex/b27-address-paths.tex`:582 | Bleibt |
| 27.4.1.29 | Jede Adresse besitzt genau einen Wurzelpfad | `B27AddressRootPathUnique` | `tex/b27-address-paths.tex`:609 | Bleibt |
| 27.4.1.30 | Der Baumelter einer Adresse ist ihr Rumpf | `B27AddressParentIsRumpf` | `tex/b27-address-paths.tex`:638 | Bleibt |
| 27.4.1.31 | Der Rumpf ist ein Baumelter | `B27AddressRumpfIsParent` | `tex/b27-address-paths.tex`:666 | Bleibt |
| 27.4.1.32 | Adresskinder sind die vorhandenen Fortsetzungen | `B27AddressChildrenSet` | `tex/b27-address-paths.tex`:690 | Bleibt |
| 27.4.1.33 | Volle Präfixmengen tragen endliche geordnete volle Binärbäume | `GoodBinaryAddressSetIsFiniteOrderedFullBinaryTree` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:4238 | Bleibt |
| 27.4.1.34 | Klammerungsbaumcodes tragen endliche geordnete volle Binärbäume | `BracketCodePositionGraphIsFiniteOrderedFullBinaryTree` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:4665 | Bleibt |
| 27.4.2.1 | Gerichtete und ungerichtete Positionskanten | `B27ForwardAddressSymmetrization` | `tex/b27-general-rooted-trees.tex`:32 | Bleibt |
| 27.4.2.2 | Positionsmengen erfüllen das allgemeine Elternsystem | `B27AddressRankedParentSystem` | `tex/b27-general-rooted-trees.tex`:53 | Bleibt |
| 27.5.1.1 | Die Konkatenation ist ein binärer Operator auf nichtleeren Wörtern | `NonemptyWordConcatenationBinaryOperation` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:4804 | Bleibt |
| 27.5.1.2 | Existenz und Eindeutigkeit der Blattwortabbildung | `TreeLeafWordExistenceUnique` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:4821 | Bleibt |
| 27.5.1.3 | Typisierung und Rekursionsgleichungen des Blattwortes | `TreeLeafWordEquations` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:4875 | Bleibt |
| 27.5.1.4 | Baumtypisierung der Klammerungsrelation | `TreeBracketingRelationTreeTyping` | `tex/b27-construction-rules.tex`:22 | Bleibt |
| 27.5.1.5 | Worttypisierung der Klammerungsrelation | `TreeBracketingRelationWordTyping` | `tex/b27-construction-rules.tex`:40 | Bleibt |
| 27.5.1.6 | Auswertung der Klammerungsrelation | `TreeBracketingRelationElimination` | `tex/b27-construction-rules.tex`:58 | Bleibt |
| 27.5.1.7 | Einführung der Klammerungsrelation | `TreeBracketingRelationIntroduction` | `tex/b27-construction-rules.tex`:77 | Bleibt |
| 27.5.1.8 | Blattregel der Klammerungsrelation | `TreeBracketingLeafIntroduction` | `tex/b27-construction-rules.tex`:105 | Bleibt |
| 27.5.1.9 | Knotenregel der Klammerungsrelation | `TreeBracketingNodeIntroduction` | `tex/b27-construction-rules.tex`:123 | Bleibt |
| 27.5.1.10 | Die Blattanfügung ist ein Klammerungsbaum | `TreeAppendLeafTyping` | `tex/b27-construction-rules.tex`:191 | Bleibt |
| 27.5.1.11 | Anfügeregel der Klammerungsrelation | `TreeBracketingAppendLeafIntroduction` | `tex/b27-construction-rules.tex`:217 | Bleibt |
| 27.5.1.12 | Existenz der Blattfunktion | `LeftBracketingLeafFunctionExistenceUnique` | `tex/b27-left-bracketing.tex`:11 | Bleibt |
| 27.5.1.13 | Kennzeichnung der Blattfunktion | `LeftBracketingLeafFunctionCharacterization` | `tex/b27-left-bracketing.tex`:41 | Bleibt |
| 27.5.1.14 | Existenz der Anfügefunktion | `LeftBracketingAppendFunctionExistenceUnique` | `tex/b27-left-bracketing.tex`:59 | Bleibt |
| 27.5.1.15 | Kennzeichnung der Anfügefunktion | `LeftBracketingAppendFunctionCharacterization` | `tex/b27-left-bracketing.tex`:105 | Bleibt |
| 27.5.1.16 | Auswertung der Anfügefunktion an einem Paar | `LeftBracketingAppendFunctionPairEquation` | `tex/b27-left-bracketing.tex`:134 | Bleibt |
| 27.5.1.17 | Existenz und Eindeutigkeit des Linksbaums | `LeftBracketingExistenceUnique` | `tex/b27-left-bracketing.tex`:191 | Bleibt |
| 27.5.1.18 | Rekursionskennzeichnung der Linksbaumabbildung | `LeftBracketingRecursionCharacterization` | `tex/b27-left-bracketing.tex`:229 | Bleibt |
| 27.5.1.19 | Typisierung der Linksbaumabbildung | `LeftBracketingTyping` | `tex/b27-left-bracketing.tex`:245 | Bleibt |
| 27.5.1.20 | Der Wert der Linksbaumabbildung ist ein Baum | `LeftBracketingValueTyping` | `tex/b27-left-bracketing.tex`:260 | Bleibt |
| 27.5.1.21 | Der Linksbaum eines Buchstabenwortes ist ein Blatt | `LeftBracketingLetterEquation` | `tex/b27-left-bracketing.tex`:275 | Bleibt |
| 27.5.1.22 | Der Linksbaum wächst durch Rechtsanfügen eines Blattes | `LeftBracketingAppendEquation` | `tex/b27-left-bracketing.tex`:302 | Bleibt |
| 27.5.1.23 | Der Linksbaum klammert sein Wort | `LeftBracketingProperty` | `tex/b27-left-bracketing.tex`:343 | Bleibt |
| 27.5.2.1 | Elementkriterium der Klammerungsmenge | `WordBracketingMembership` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:5006 | Bleibt |
| 27.5.2.2 | Relation und Zugehörigkeit zur Klammerungsmenge | `TreeBracketingRelationMembership` | `tex/b27-bracketing-existence.tex`:5 | Bleibt |
| 27.5.2.3 | Ein Klammerungsbaum bezeugt die Nichtleerheit | `TreeBracketingRelationNonempty` | `tex/b27-bracketing-existence.tex`:80 | Bleibt |
| 27.5.2.4 | Ein Zeuge aus einer nichtleeren Klammerungsmenge | `WordBracketingNonemptyRelationWitness` | `tex/b27-bracketing-existence.tex`:96 | Bleibt |
| 27.5.2.5 | Jedes nichtleere Wort wird von einem Baum geklammert | `TreeBracketingExistence` | `tex/b27-bracketing-existence.tex`:118 | Bleibt |
| 27.5.2.6 | Existenz einer Klammerung | `WordBracketingExistence` | `tex/b27-bracketing-existence.tex`:134 | Bleibt |
| 27.5.3.1 | Existenz und Eindeutigkeit der Baumauswertung | `TreeEvaluationExistenceUnique` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:5037 | Bleibt |
| 27.5.3.2 | Typisierung und Rekursionsgleichungen der Baumauswertung | `TreeEvaluationEquations` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:5085 | Bleibt |
| 27.5.3.3 | Auswertung einer Blattanfügung | `TreeAppendLeafEvaluation` | `tex/b27-left-bracketing-evaluation.tex`:10 | Bleibt |
| 27.5.3.4 | Die Auswertung des Linksbaums ist die Linksfaltung | `LeftBracketingEvaluation` | `tex/b27-left-bracketing-evaluation.tex`:52 | Bleibt |
| 27.6.1.1 | Eindeutiger Isomorphismus freier Wortstrukturen | `WordStructureUniqueIsomorphism` | `tex/b27-structural-axioms.tex`:18 | Bleibt |
| 27.6.1.2 | Eindeutiger Isomorphismus freier Baumstrukturen | `BinaryTreeStructureUniqueIsomorphism` | `tex/b27-structural-axioms.tex`:57 | Bleibt |
| 27.6.1.3 | Freie Strukturen über dem leeren Alphabet | `FreeStructuresEmptyAlphabet` | `tex/b27-structural-axioms.tex`:97 | Bleibt |

## Vollständige Liste der gelesenen aktiven Quellen

- `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex` (5217 Zeilen)
- `tex/b27-word-generated-set.tex` (479 Zeilen)
- `tex/b27-word-characterization.tex` (161 Zeilen)
- `tex/b27-word-length.tex` (65 Zeilen)
- `tex/b27-word-early-core.tex` (211 Zeilen)
- `tex/b27-word-early-minimality.tex` (42 Zeilen)
- `tex/b27-word-structure-axioms.tex` (134 Zeilen)
- `tex/b27-word-concrete-model.tex` (26 Zeilen)
- `tex/b27-word-structure-consequences.tex` (148 Zeilen)
- `tex/b27-word-proof-helpers.tex` (4 Zeilen)
- `tex/b27-word-axiomatic-recursion.tex` (352 Zeilen)
- `tex/b27-word-canonical-isomorphism.tex` (119 Zeilen)
- `tex/b27-word-concatenation-adjunction.tex` (88 Zeilen)
- `tex/b27-word-concatenation-successor.tex` (38 Zeilen)
- `tex/b27-associativity-from-axioms.tex` (23 Zeilen)
- `tex/b27-word-decomposition-from-axioms.tex` (88 Zeilen)
- `tex/b27-word-end-operations.tex` (306 Zeilen)
- `tex/b27-word-finite-induction.tex` (61 Zeilen)
- `tex/b27-finite-word-induction-from-axioms.tex` (12 Zeilen)
- `tex/b27-nonempty-induction-proof.tex` (60 Zeilen)
- `tex/b27-nonempty-recursion-from-axioms.tex` (145 Zeilen)
- `tex/b27-tree-example.tex` (34 Zeilen)
- `tex/b27-tree-early-foundations.tex` (335 Zeilen)
- `tex/b27-tree-early-axioms.tex` (422 Zeilen)
- `tex/b27-tree-axiomatic-recursion.tex` (717 Zeilen)
- `tex/b27-tree-recursion-specification.tex` (14 Zeilen)
- `tex/b27-tree-decomposition-from-axioms.tex` (87 Zeilen)
- `tex/b27-tree-induction-from-axioms.tex` (19 Zeilen)
- `tex/b27-tree-recursion-from-axioms.tex` (22 Zeilen)
- `tex/b27-tree-canonical-isomorphism.tex` (205 Zeilen)
- `tex/b27-tree-recursor.tex` (350 Zeilen)
- `tex/b27-graft-proof-lemmas.tex` (190 Zeilen)
- `tex/b27-position-recursor-existence.tex` (91 Zeilen)
- `tex/b27-address-paths.tex` (739 Zeilen)
- `tex/b27-general-rooted-trees.tex` (98 Zeilen)
- `tex/b27-construction-rules.tex` (247 Zeilen)
- `tex/b27-left-bracketing.tex` (443 Zeilen)
- `tex/b27-bracketing-existence.tex` (146 Zeilen)
- `tex/b27-left-bracketing-evaluation.tex` (200 Zeilen)
- `tex/b27-structural-axioms.tex` (215 Zeilen)
