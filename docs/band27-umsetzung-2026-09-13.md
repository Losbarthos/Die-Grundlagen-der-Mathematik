# Umgesetzt: Band 27 und die Teilmengenregel

**Ergänzende Nachprüfung:** Die anschließende
[Prüfung aller Bände bis 27](<C:/Latex/Die-Grundlagen-der-Mathematik/docs/band01-27-teilmengen-nachpruefung-2026-09-13.md>)
hat weitere Kürzungsmöglichkeiten sowie Begründungs- und Entladungsfehler
gefunden. Dieses Dokument beschreibt den damaligen Umsetzungsstand;
die bestandenen technischen Verweisprüfungen ersetzen keinen vollständigen
mathematischen Nachweis der Beweistabellen.

Stand: 13. September 2026. Die Nummern in der linken Spalte beziehen sich auf die
[Strukturprüfung vor dem Umbau](<C:/Latex/Die-Grundlagen-der-Mathematik/docs/band27-strukturpruefung-2026-09-13.md>), die Nummern
rechts auf die neu erzeugten Einzelbände.

## Teilmengeneinführung in Band 3

**Theorem 3.5.1.1** steht unmittelbar nach der Definition der Teilmenge:

\[
 [x\in M]\ \vdots\ x\in N\quad\vdash\quad M\subseteq N.
\]

Die lokale Annahme wird entlassen. Die Variable darf weder in den Mengenparametern
noch in den übrigen offenen Annahmen frei vorkommen. Der einmalige Beweis führt
Implikation und Allquantor ein und wendet dann die Teilmengendefinition an.
Die Aufrufnotation `[i]⋮j` bezeichnet ausdrücklich die lokale Teilableitung.

**217 Anwendungen in 20 Bänden** wurden auf die neue Regel umgestellt. Die
betroffenen Anwendungsbeweise sparen **netto 58 Beweiszeilen**. Bei vielen Anwendungen bleibt
die Zeilenzahl gleich; dort ersetzt ein Regelverweis die verschachtelte
Begründung aus Definition, Allquantor- und Implikationseinführung.

| Band | Anwendungen |
|---|---:|
| 03 | 54 |
| 04 | 1 |
| 05 | 32 |
| 06 | 2 |
| 07 | 2 |
| 08 | 8 |
| 10 | 10 |
| 11 | 6 |
| 12 | 1 |
| 13 | 2 |
| 19 | 21 |
| 20 | 14 |
| 26 | 2 |
| 27 | 10 |
| 28 | 23 |
| 38 | 1 |
| 40 | 11 |
| 45 | 1 |
| 46 | 15 |
| 48 | 1 |

Die Einsparung setzt sich zusammen aus zwölf Zeilen in Band 3, netto 18 in
Band 5, drei in Band 10, zwei in Band 20 und 23 in den übrigen Bänden.
In zwei Graphbeweisen in Band 5 wurden drei notwendige Zeilen ergänzt, damit
die lokale Annahme tatsächlich ein beliebiges Element des Graphen betrifft;
die Paarzerlegung wird dort nun ausdrücklich begründet. Diese Ergänzung ist
in der Nettozahl bereits berücksichtigt.

Geprüft wurden auch die verbliebenen Definitionsverweise. Elf echte aktive
Verwendungen bleiben sinnvoll: der Beweis der neuen Regel selbst, sieben
Eliminationen, zwei Äquivalenzumformungen und ein Abschluss einer bereits
allquantifizierten Induktionsaussage. Acht Treffer stammen aus auskommentierten
historischen TeX-Blöcken; sieben betreffen andere Definitionen. Keine dieser
Stellen erhält durch die neue Einführungsregel einen kürzeren direkten Beweis.

## Allgemeine Sätze aus Band 27

Alle **46 Hauptsatzstellen und der separat nutzbare Teilbeweis H2** aus der
Strukturprüfung wurden verlagert oder mit einer allgemeinen Fassung
zusammengeführt. Die zugehörigen Definitionen sind mitgezogen. Die Wortaxiome,
die Wortinduktion und die eigentliche Wort- und Klammerungstheorie bleiben in
Band 27.

- Band 2 enthält die allgemeine eindeutige Existenz aus einem festen Zeugen.
- Band 3 enthält die beschränkte Fassung, Paarmengenregeln und Termbilder.
  Die Vereinigung einer Einermenge steht unmittelbar bei der Vereinigung.
- Band 5 enthält die allgemeinen Funktionsfaserregeln.
- Band 7 enthält zweistellige Termbilder, Operatorgraphen und einen gemeinsamen
  Faserfilter für beliebige Produkte. Wort- und Baumrekursion verwenden nun
  dieselben Filterregeln.
- Band 10 enthält die Regeln für Indizes und die endliche Rückwärtsinduktion.
- Band 11 enthält zusätzlich die allgemeine Graphkorrespondenz
  `F:D→A ⇒ D≈F`.
- Band 20 enthält die Kardinalzahlgesetze und zusätzlich die Endlichkeit und
  Kardinalität allgemeiner Funktionsgraphen mit endlichem Definitionsbereich.
- Band 21 enthält die entsprechenden Folgenspezialisierungen und die
  Eindeutigkeit der Folgenlänge.
- Band 26 enthält die allgemeinen Weg- und Elternsystemregeln. Der Nullweg
  wird jetzt durch `{(0,r)}` dargestellt und benötigt keinen Wortbegriff.

Die vorhandenen Formelkennungen bleiben überwiegend erhalten, damit Verweise
stabil bleiben. Bei den zwei zusammengeführten Baumfiltersätzen verwenden die
Quellen jetzt ausdrücklich die gemeinsamen Filterkennungen.

| Bisher in Band 27 | Neuer Satz | Stabile Kennung des verwendeten Ergebnisses |
|---|---|---|
| 27.2.2.1 | 3.13.3.16 | `B27AdjoinedPairMembership` |
| 27.2.2.2 | 3.13.3.17 | `B27AdjoinedPairOldFiber` |
| 27.2.2.3 | 5.3.3.22 | `B27AdjoinedPairNewFiber` |
| 27.2.2.4 | 5.3.3.23 | `B27FunctionBoundedUniqueValue` |
| 27.2.2.5 | 3.8.3.7 | `B27UniqueFromSingletonPredicate` |
| 27.2.2.6 | 20.3.8.13 | `B27FiniteCardEmpty` |
| 27.2.2.7 | 20.3.8.14 | `B27FiniteCardAdjunction` |
| 27.2.2.8 | 20.3.8.15 | `B27FiniteCardinalityInduction` |
| 27.2.2.9 | 21.3.2.4 | `EarlyWordAdjunctionGraphTyping` |
| 27.2.2.10 | 21.3.2.1 | `WordGraphEquinumerousDomain` |
| 27.2.2.11 | 21.3.2.2 | `WordGraphFinite` |
| 27.2.2.12 | 21.3.2.3 | `FiniteWordCardinalityFromTyping` |
| 27.2.2.14 | 21.3.2.5 | `B27FiniteGraphLastAdjunction` |
| 27.2.2.19 (H2) | 21.3.2.6 | `FiniteWordLengthUniquenessPart` |
| 27.2.6.4 | 2.10.9.7 | `WordUniqueExistenceFromWitness` |
| 27.2.6.8 | 3.18.1.2 | `B27TermImageMembership` |
| 27.2.6.9 | 3.18.1.3 | `B27TermImageSingleton` |
| 27.2.6.10 | 3.18.1.4 | `B27TermImageUnion` |
| 27.2.6.11 | 3.13.2.9 | `B27SingletonUnion` |
| 27.2.6.12 | 5.2.3.3 | `B27FunctionGraphFiber` |
| 27.2.6.13 | 3.18.1.5 | `B27TermImageSubset` |
| 27.2.6.14 | 3.18.1.6 | `B27TermImagePointwiseEquality` |
| 27.2.6.17 | 7.3.1.23 | `WordRecursionFilterSubset` |
| 27.2.6.18 | 7.3.1.24 | `WordRecursionFilterMembership` |
| 27.2.6.23 | 7.3.1.25 | `WordRecursionFilterOwnFiber` |
| 27.3.3.1 | 7.3.1.22 | `TreeCodeBinaryTermImageMembership` |
| 27.3.4.12 | 7.3.1.24 | `WordRecursionFilterMembership` |
| 27.3.4.13 | 7.3.1.23 | `WordRecursionFilterSubset` |
| 27.4.1.15 | 3.11.3.30 | `B27PairIntersectionFullness` |
| 27.4.1.16 | 3.11.3.31 | `B27EmptyOrDistinctPairWitnesses` |
| 27.4.1.19 | 10.4.11.1 | `B27SmallerIndexInSegment` |
| 27.4.1.20 | 26.2.2.28 | `B27PathStepData` |
| 27.4.1.21 | 10.4.11.2 | `B27SuccessorIndexBackward` |
| 27.4.1.22 | 10.4.11.3 | `B27FiniteBackwardInduction` |
| 27.4.1.24 | 26.2.2.29 | `B27SimplePathFamilyPairIntroduction` |
| 27.4.1.25 | 26.2.2.30 | `B27SimplePathFamilyPairElimination` |
| 27.4.1.29 | 26.2.2.31 | `B27RootPathSingleton` |
| 27.4.1.30 | 26.2.2.32 | `B27RootPathExtendExistence` |
| 27.4.2.1 | 26.4.3.1 | `B27FiniteRootedChildrenFinite` |
| 27.4.2.2 | 26.4.3.2 | `B27RankedParentGraphData` |
| 27.4.2.3 | 26.4.3.3 | `B27RankedPathHeight` |
| 27.4.2.4 | 26.4.3.4 | `B27RankedDirectedReachability` |
| 27.4.2.5 | 26.4.3.5 | `B27RankedRootPathForward` |
| 27.4.2.6 | 26.4.3.6 | `B27RankedDirectedPathUnique` |
| 27.4.2.7 | 26.4.3.7 | `B27RankedSymmetricRootPaths` |
| 27.4.2.8 | 26.4.3.8 | `B27RankedParentSystemTree` |
| 27.4.2.9 | 26.4.3.9 | `B27RankedParentEdgesAgree` |

Die beiden bisherigen Baumfilterstellen verweisen deshalb auf dieselben neuen
Sätze wie ihre Wortgegenstücke. Drei zusätzlich formulierte allgemeine Sätze
tragen die Kennungen `FunctionGraphEquinumerousDomain`, `FiniteFunctionGraph`
und `FiniteFunctionGraphCardinality`.

## Anzahlnotation und Motivation

Die Anzahl einer endlichen Menge wird durchgängig als `#(M)` gesetzt. Im
Quelltext heißt das Makro `\FiniteCard`; umgestellt sind Fachbände,
ausgelagerte Beweise, Formelverweise und Übersichten. Band 20 erläutert
ausdrücklich, dass diese Definition nur endliche Mengen betrifft. Die
Wortlänge behält ihre Schreibweise `|w|`. Der alte Makroname ist lediglich
als Alias für nicht mehr eingebundene historische Quellen erhalten.

Die Einleitung zur Anfügungsfunktion in Band 27 erklärt jetzt ihren Zweck:
Der bereits bekannte Erzeugungsschritt `J(u,a)` wird als Funktion
`σ_A:A*×A→A*` bereitgestellt. Damit entsteht im konkreten Modell genau die
Komponente, die später in der abstrakten Wortstruktur als Anfügungsfunktion
verwendet wird.

## Prüfung

Die neuen Anwendungen wurden auf Anfangsannahmen, Endzeilen, Entladungen,
freie Variablen und fortlaufende Zeilenverweise geprüft. Die umnummerierten
Mehrteilbeweise in Band 28 wurden zusätzlich gegen die Sicherung abgeglichen.
Die neuen allgemeinen Graph- und Folgenfassungen wurden unabhängig auf
ihre Voraussetzungen und ihre Einfügereihenfolge geprüft. Dabei wurden auch
einige bereits vorhandene falsche Zeilenlabels und gerichtete
Gleichheitseinsetzungen an den bearbeiteten Stellen berichtigt. Drei
Äquivalenzersetzungen sind jetzt durch tatsächliche Äquivalenzen begründet.
Beim Produktkriterium in Band 7 benötigt diese Korrektur sieben zusätzliche
Beweiszeilen; sie gehört ebenso wie der Beweis der neuen Regel selbst nicht
zu den oben gezählten Kürzungen der Anwendungsbeweise.

Alle 49 Einzelbände sind im Ausgabeordner neu bereitgestellt; der Gesamtband
ist ebenfalls aktualisiert. Der abschließende Prüflauf hat die Formelregister,
die Satznummern und die Verweise aller Einzelbände mit dem Gesamtband
abgeglichen. Es gibt keine unaufgelösten oder mehrdeutigen Formelverweise.

Die veröffentlichten Einzelbände umfassen zusammen 2847 PDF-Seiten.
Geprüft wurden 13819 interne Links und 38173 Verweise zwischen
den Einzelbänden. Der Gesamtband umfasst 2818 Seiten; seine
52042 geprüften Links führen ausschließlich innerhalb derselben Datei.

Band 27 umfasst nun 225 statt zuvor 258 Seiten. Die neu eingefügten
und wesentlich umgestalteten Abschnitte wurden zusätzlich an gerenderten
PDF-Seiten geprüft. Dabei gefundene Umbruchprobleme in den Bänden 3, 7, 20,
21, 26, 27 und 28 sind korrigiert und nachgeprüft. Diese Sichtprüfung war
eine gezielte Stichprobe, keine vollständige Prüfung sämtlicher Seiten.

Die technischen Einzelprotokolle und die Sicherung des Ausgangsstands liegen
unter `tmp/b27-foundation-migration`.
