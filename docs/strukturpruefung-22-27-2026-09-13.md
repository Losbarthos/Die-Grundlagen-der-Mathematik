# Kritische Strukturprüfung B22–B27

Stand: 13.09.2026. Quellenlektüre, aktuelle Register und aktive Includes; keine Manuskriptänderungen, kein Build. Prüfmaßstab ist die fachlich sinnvolle allgemeinere Aussage und ihre Wiederverwendung. Wort-/Baumnotation allein ist kein Grund, einen Kandidaten abzulehnen. Dieser Bericht ergänzt und präzisiert die enger auf unverändert formulierte Hauptsätze bezogene frühere Notiz `remaining-b27-structure.md`.

## Ergebnis und Priorität

**P1 (klar):** Aus B26 fünf reine arithmetische Sätze nach B10, zwei bereits als reine Folgensätze formulierte Sätze nach B21; den allgemeinen gerichteten Pfadblock nach B22 und den ungerichteten Umkehr-/Zyklusblock nach B23. Das betrifft ganze Gruppen einschließlich ihrer Definitionen, nicht isolierte Sätze.

**P1 (sinnvolle Verallgemeinerung):** Den Koordinaten-/Graphbeweis der endlichen Konkatenation aus B27 als Theorie der Konkatenation endlicher Folgen nach B21 verlegen. Die Wortfassung bleibt als kurze Anwendung; primitive Wortanfügung und Assoziativität aus W0–W3 bleiben in B27.

**P2:** Allgemeine gemeinsame Stufe wachsender Mengenfolgen aus 27.3.2.11 nach B21; Vermeidung des ersten Werts durch den Schwanz einer injektiven Folge aus 26.2.2.9 ebenfalls nach B21. Der Zusammenhang zweier Wege mit gemeinsamer Wurzel aus 26.3.3.1 gehört sachlich zu B23 und kann den Aufbau von B25 vorbereiten.

**Korrektur eines früheren Zielorts, nicht neu zählen:** Die fünf bereits B27→B26 verschobenen allgemeinen Pfadregeln passen mit dem nun vollständig betrachteten Pfadblock besser nach B22. Der ebenfalls bereits verschobene Elternsystemblock ist als Baumkriterium in B26 dagegen gut eingeordnet.

## Abdeckung

| Band | Aktive Quellen | Hauptsätze im Register | Definitionen im Register | Prüfung / Befund |
| --- | ---: | ---: | ---: | --- |
| B22 Gerichtete Graphen | 1 | 18 | 9 | Gesamte Hauptquelle, Nachbarschaften, Umkehrgraph, induzierter Graph, Walk/Pfad/Zyklus/Erreichbarkeit. Allgemeine Mengentechnik ist weitgehend Anwendung früherer Grundlagen; dieser Band ist der passende Zielort der gerichteten Pfadoperationen aus B26. |
| B23 Ungerichtete Graphen | 1 | 7 | 2 | Gesamte Hauptquelle einschließlich induzierter Graphen. Symmetriebeweise verwenden die gerichtete Grundlage; keine neue unabhängig allgemeine Aussage entdeckt. Passender Zielort von Pfadumkehr und dem Zyklusargument aus B26. |
| B24 Schlichte ungerichtete Graphen | 1 | 4 | 1 | Gesamte Hauptquelle. Die Schleifenfreiheit und ihre Vererbung auf induzierte Teilgraphen sind angemessene Spezialisierungen, keine Wiederholung des gerichteten Funktionalitäts-/Mengenbeweises. |
| B25 Zusammenhängende Graphen | 1 | 2 | 1 | Gesamte Hauptquelle. Sehr kurzer Strukturband mit zwei Zugriffssätzen. Kein allgemeiner Beweisblock zum Auslagern; allgemeine Erreichbarkeitsfolgen aus B22/B23 könnten hier später den Zusammenhang ausbauen. |
| B26 Bäume | 4 | 78 | 20 | Hauptquelle plus alle drei aktiven migrierten Pfad-/Elternmodule. Hauptfunde: Arithmetik, reine Folgen, allgemeine Pfadoperationen vor Beginn der eigentlichen Baumtheorie. |
| B27 Endliche Wörter und Klammerungsbäume | 40 | 233 | 49 | Gesamte Hauptquelle und 39 aktive Includes, einschließlich struktureller Axiome in Kapitel 6; ergänzend alle 114 ausdrücklich formulierten Teilbeweis-/Induktionsblöcke auf ihre Bedeutung geprüft. Hauptfunde: Folgenkonkatenation und gemeinsame Stufe. |

Insgesamt 48 aktive Quellen und 342 Hauptsätze. Dies ist eine inhaltliche Struktur- und Abhängigkeitsprüfung, keine erneute formale Verifikation aller Beweiszeilen. Automatische Register-Fundstellen mit mehrfach vorkommendem Titel wurden für die unten aufgeführten Kandidaten an den eindeutigen IDs in der Quelle nachgeprüft.

## A. B26: fünf bereits allgemeine arithmetische Sätze (P1)

Die fünf Aussagen enthalten weder Graphen noch Wege. Zusammen umfassen ihre aktuellen Beweise 66 explizite Zeilen (13+13+16+9+15). Für eine Verlagerung ist keine Verallgemeinerung erforderlich, lediglich der wegbezogene Titel der ersten beiden Sätze sollte neutralisiert werden.

| Aktuelle Nr. | Exakter Titel / ID | Quelle:Zeile | Ziel und Voraussetzungen |
| --- | --- | --- | --- |
| 26.2.2.1 | Indexangaben für einen Weganfang — `FinitePathPrefixIndexData` | `Bd. 26 - Bäume.tex`:235 | B10 nach `PeanoNatSegLeqSubsetForward` (10.4.6.22). Aussage: n∈N,k∈N_<n+1 ⇒ k∈N, k≤n und N_<k+1⊆N_<n+1. Benötigt die Anfangsabschnitts-/Nachfolgerkriterien 10.4.6.13, .21, .22 und Addition. |
| 26.2.2.2 | Verschiebung eines Wegindex um eins — `FinitePathIndexShiftOne` | `Bd. 26 - Bäume.tex`:276 | B10 im selben Indexabschnitt nach den natürlichen Anfangsabschnitten. Aussage: n∈N,i∈N_<n ⇒ i+1∈N_<n+1. Benötigt `PeanoNatSegStrictMembership`, `PeanoAddLeftStrictMonotone` und Kommutativität; lässt sich gegebenenfalls schon mit allgemeiner Verschiebungsmitgliedschaft ableiten. |
| 26.2.2.22 | Linkskürzung einer nichtstrikten Summenungleichung — `PeanoAddLeftLeqCancellation` | `Bd. 26 - Bäume.tex`:1869 | B10 nach `PeanoAddLeftCancellation` (10.4.5.27) und der additiven Charakterisierung von ≤. Aussage: a+b≤a+c ⇒ b≤c für a,b,c∈N. Der Beweis benutzt nur Addition, Assoziativität, Linkskürzung und einen Abstandszeugen. |
| 26.2.2.23 | Nichtstrikte Ordnung ohne Gleichheit ist strikt — `PeanoLeqNeqStrict` | `Bd. 26 - Bäume.tex`:1911 | B10 direkt nach `PeanoLeqSplit` (10.4.5.17). Aussage: m≤n und m≠n ⇒ m<n. Im aktuellen neunzeiligen Beweis nur die Zerlegung m<n∨m=n und Logik; keine Graphabhängigkeit. |
| 26.2.2.24 | Strikte Monotonie der Summe in beiden Summanden — `PeanoAddStrictMonotoneBoth` | `Bd. 26 - Bäume.tex`:1930 | B10 nach `PeanoLtTransitive` (10.4.10.7), solange dessen früherer Platz unverändert bleibt. Aussage: a<b,c<d ⇒ a+c<b+d. Benötigt `PeanoAddLeftStrictMonotone` (10.4.5.25), Kommutativität und Transitivität. Nicht vor den erst später eingeführten Transitivitätssatz setzen. |

Diese Hilfssätze werden bereits im allgemeinen Pfadblock und teilweise im Elternsystembeweis wiederverwendet. Sie erst im Baumband einzuführen erschwert auch die sinnvolle frühere Platzierung dieser Anwendungen.

## B. B26: echte Folgengrundlagen (P1/P2)

| Aktuelle Nr. | Exakter Titel / ID | Quelle:Zeile | Ziel und Voraussetzungen |
| --- | --- | --- | --- |
| 26.2.2.10 | Das Bild des Schwanzsegments bleibt im Pfadbild — `FinitePathTailImageSubset` | `Bd. 26 - Bäume.tex`:872 | P1, B21 nach nullbasierten endlichen Folgen/Indexverschiebung. Bereits reine Aussage: bei p:N_<((n+1)+1)→V, q:N_<n+1→V und q(i)=p(i+1) gilt im(q)⊆im(p). 14 Beweiszeilen. Benötigt Bildmitgliedschaft aus B5 und den oben nach B10 verschobenen `FinitePathIndexShiftOne`. |
| 26.2.2.25 | Ein endlicher Weg ist durch zwei anschließende Abschnitte bestimmt — `FinitePathSplitRigidity` | `Bd. 26 - Bäume.tex`:1966 | P1, B21 als „Eine endliche Folge ist durch zwei anschließende Abschnitte bestimmt“. Bereits ohne Graph-/Pfadprämisse formuliert: gleiche Abschnittslängen und gleiche Anfangs-/umindizierte Endabschnitte ergeben gleiche gesamte Folge samt Länge. 84 Beweiszeilen. Benötigt Funktionsextensionalität 5.2.3.17, Einschränkung aus B5, Indexarithmetik B10 und die dorthin verlegte `PeanoAddLeftLeqCancellation`. Auf gemeinsamen Randindex achten: Die Abschnitte überlappen an der Schnittstelle; dies ist nicht wörtlich eine disjunkte Konkatenation. |
| 26.2.2.9 | Das Schwanzsegment meidet den ersten Knoten — `FinitePathTailAvoidsFirstVertex` | `Bd. 26 - Bäume.tex`:757 | P2, B21 nach einer allgemeinen Schwanz-/Umindizierungsregel. Natürliche Verallgemeinerung: ersetze GraphStruct und DirectedPath durch p:N_<((n+1)+1) inj V; die übrigen Voraussetzungen bleiben. Schluss p(0)∉q[N_<n+1]. Im aktuellen 43-Zeilen-Beweis werden die Graphannahmen ausschließlich verwendet, um die Injektivität von p zu entnehmen (alte Zeilen11–12); die Kantendaten spielen keine Rolle. Ein kleiner allgemeiner Satz über Bildvermeidung unter Injektionen wäre auch in B6 möglich, die konkrete Folgenfassung gehört nach B21. |

`FinitePathFreshEndpointExtension` (26.2.2.11) benutzt dagegen bereits `FreshExtMapBijective` und `FreshExtMapOnBase` aus der früheren Funktionentheorie. Dort sollte kein vermeintlich neues allgemeines Erweiterungstheorem erfunden werden. Der graphbezogene Schluss ist nach B22 zu verlegen; ein gebündeltes Folgencorollar in B21 wäre nur eine zusätzliche Kürzungsmöglichkeit.

## C. B26: allgemeine Wege vor der Baumtheorie (P1)

Der aktuelle Haupttext führt ab Zeile134 die Menge gespeicherter Wege und ab Zeile235 deren Operationen ein. Die erste Walddefinition folgt erst in Zeile2713. Dieser große Vorbau verwendet an vielen Stellen bloß beliebige gerichtete Graphen, an anderen beliebige ungerichtete Graphen. Ihn geschlossen in B26 zu belassen ist der größte strukturelle Fremdkörper im geprüften Graphenbereich.

### C1. Nach B22: gerichtete Operationen

Ziel: neuer Abschnitt/gegebenenfalls neues Kapitel „Operationen mit endlichen Wegen“ nach den vorhandenen Walk-/Pfad- und Erreichbarkeitsdefinitionen in B22. B22 enthält damit alle Grundbegriffe, bevor die folgenden Regeln eingeführt werden. Keine dieser nachstehenden Aussagen benötigt Symmetrie, Schleifenfreiheit, Zusammenhang oder einen Baum.

Mitverschieben:

- `FiniteSimplePathFamilyDef`, aktuelle Definition26.2.1.1, Haupttext:134, samt der Schreibweise `GraphPathsBetween` (derzeit lokale Makrodefinition oben in B26). Die Wege sind gespeicherte Paare (n,p), also ohne Bäume definierbar.
- `FinitePathTransportPropertyDef`, aktuelle Definition26.2.2.1, Haupttext:1221, samt `FinitePathTransportProperty`.
- `FinitePathSuffixPropertyDef`, aktuelle Definition26.2.2.3, Haupttext:1558, samt `FinitePathSuffixProperty`.

| Aktuelle Nr. | Exakter Titel / ID | Quelle:Zeile | Ziel und Voraussetzungen |
| --- | --- | --- | --- |
| 26.2.1.1 | Zugriff auf einen endlichen einfachen Weg — `FiniteSimplePathFamilyMembership` | `Bd. 26 - Bäume.tex`:159 | B22 nach der mitverschobenen Wegfamilien-Definition; benötigt nur B22-Walk/Pfad und Mengen-/Funktionstypisierung. |
| 26.2.1.2 | Knotenfolge eines gespeicherten Weges — `FiniteSimplePathSequence` | `Bd. 26 - Bäume.tex`:190 | B22 nach der mitverschobenen Wegfamilien-Definition; benötigt nur B22-Walk/Pfad und Mengen-/Funktionstypisierung. |
| 26.2.1.3 | Endpunkte eines Weges gehören zum Träger — `FiniteSimplePathEndpointTyping` | `Bd. 26 - Bäume.tex`:205 | B22 nach der mitverschobenen Wegfamilien-Definition; benötigt nur B22-Walk/Pfad und Mengen-/Funktionstypisierung. |
| 26.2.2.3 | Zugriff auf die Typdaten eines endlichen Pfads — `FinitePathTyping` | `Bd. 26 - Bäume.tex`:309 | B22 nach Walk/Pfad-Definitionen; Funktionen, Einschränkung, Injektivität und B10-Indizes sind schon verfügbar. Die früheren reinen Index-/Folgenhilfen zuvor nach B10/B21 verlegen. |
| 26.2.2.4 | Ein endlicher Walk ist als Relation typisiert — `FiniteWalkPowerSetTyping` | `Bd. 26 - Bäume.tex`:337 | B22 nach Walk/Pfad-Definitionen; Funktionen, Einschränkung, Injektivität und B10-Indizes sind schon verfügbar. Die früheren reinen Index-/Folgenhilfen zuvor nach B10/B21 verlegen. |
| 26.2.2.5 | Ein endlicher Pfad ist als Relation typisiert — `FinitePathPowerSetTyping` | `Bd. 26 - Bäume.tex`:371 | B22 nach Walk/Pfad-Definitionen; Funktionen, Einschränkung, Injektivität und B10-Indizes sind schon verfügbar. Die früheren reinen Index-/Folgenhilfen zuvor nach B10/B21 verlegen. |
| 26.2.2.6 | Anfangsabschnitt eines endlichen Walks — `FiniteWalkInitialSegment` | `Bd. 26 - Bäume.tex`:406 | B22 nach Walk/Pfad-Definitionen; Funktionen, Einschränkung, Injektivität und B10-Indizes sind schon verfügbar. Die früheren reinen Index-/Folgenhilfen zuvor nach B10/B21 verlegen. |
| 26.2.2.7 | Anfangsabschnitt eines endlichen Pfads — `FinitePathInitialSegment` | `Bd. 26 - Bäume.tex`:522 | B22 nach Walk/Pfad-Definitionen; Funktionen, Einschränkung, Injektivität und B10-Indizes sind schon verfügbar. Die früheren reinen Index-/Folgenhilfen zuvor nach B10/B21 verlegen. |
| 26.2.2.8 | Schwanzsegment eines endlichen Pfads — `FinitePathTailSegment` | `Bd. 26 - Bäume.tex`:568 | B22 nach Walk/Pfad-Definitionen; Funktionen, Einschränkung, Injektivität und B10-Indizes sind schon verfügbar. Die früheren reinen Index-/Folgenhilfen zuvor nach B10/B21 verlegen. |
| 26.2.2.11 | Frische Fortsetzung eines endlichen Pfads — `FinitePathFreshEndpointExtension` | `Bd. 26 - Bäume.tex`:911 | B22 nach Anfangs-/Schwanzoperationen; gerichtete Kante (p(n),y), frische Erweiterung beziehungsweise Abschneiden beim Auftreten von y. Keine Ungerichtetheit nötig. |
| 26.2.2.12 | Fortsetzung eines Pfads um eine Kante — `FinitePathEndpointStep` | `Bd. 26 - Bäume.tex`:1135 | B22 nach Anfangs-/Schwanzoperationen; gerichtete Kante (p(n),y), frische Erweiterung beziehungsweise Abschneiden beim Auftreten von y. Keine Ungerichtetheit nötig. |
| 26.2.2.13 | Transportbasis — `FinitePathTransportBase` | `Bd. 26 - Bäume.tex`:1236 | B22 nach Transport-Prädikatsdefinition und `FinitePathEndpointStep`; die Induktion fügt einen gerichteten Walk an einen Pfad an und entfernt Wiederholungen. Keine Umkehrung verwendet. |
| 26.2.2.14 | Transportschritt — `FinitePathTransportStep` | `Bd. 26 - Bäume.tex`:1257 | B22 nach Transport-Prädikatsdefinition und `FinitePathEndpointStep`; die Induktion fügt einen gerichteten Walk an einen Pfad an und entfernt Wiederholungen. Keine Umkehrung verwendet. |
| 26.2.2.15 | Transport entlang eines endlichen Walks — `FinitePathTransportAlongWalk` | `Bd. 26 - Bäume.tex`:1323 | B22 nach Transport-Prädikatsdefinition und `FinitePathEndpointStep`; die Induktion fügt einen gerichteten Walk an einen Pfad an und entfernt Wiederholungen. Keine Umkehrung verwendet. |
| 26.2.2.19 | Schwanzbasis — `FinitePathSuffixBase` | `Bd. 26 - Bäume.tex`:1571 | B22 nach Schwanz-Prädikatsdefinition und `FinitePathTailSegment`; benötigt natürliche Induktion und Umindizierung, keine Symmetrie. |
| 26.2.2.20 | Schwanzschritt — `FinitePathSuffixStep` | `Bd. 26 - Bäume.tex`:1623 | B22 nach Schwanz-Prädikatsdefinition und `FinitePathTailSegment`; benötigt natürliche Induktion und Umindizierung, keine Symmetrie. |
| 26.2.2.21 | Endabschnitt eines endlichen Pfads — `FinitePathFinalSegment` | `Bd. 26 - Bäume.tex`:1798 | B22 nach Schwanz-Prädikatsdefinition und `FinitePathTailSegment`; benötigt natürliche Induktion und Umindizierung, keine Symmetrie. |

### C2. Nach B23: Umkehrung und zwei Wegbögen

Ziel: eigener Abschnitt nach dem ungerichteten Graphbegriff und `UndirectedAdjacencySymmetric`. Die bisherigen gerichteten Operationen liegen dann bereits in B22.

Die **Umkehrung benötigt Symmetrie**: aus einer ursprünglichen Kante muss die rückwärts durchlaufene Kante folgen. Die drei Umkehrsätze einschließlich `FinitePathReversalPropertyDef` (aktuelle Definition26.2.2.2, Haupttext:1354; lokale Makrodefinition `FinitePathReversalProperty`) bilden deshalb eine Einheit in B23. Das folgende Zyklusargument benutzt die Umkehrung; es gehört nicht in den rein gerichteten Block.

| Aktuelle Nr. | Exakter Titel / ID | Quelle:Zeile | Ziel und Voraussetzungen |
| --- | --- | --- | --- |
| 26.2.2.16 | Umkehrbasis — `FinitePathReversalBase` | `Bd. 26 - Bäume.tex`:1368 | B23, mit der Umkehr-Prädikatsdefinition. Basisfall des selben Umkehrbeweises. |
| 26.2.2.17 | Umkehrschritt — `FinitePathReversalStep` | `Bd. 26 - Bäume.tex`:1390 | B23 nach gerichteter Schwanz-/Erweiterungsregel; hier kommt die umgekehrte Kante aus Symmetrie hinzu. |
| 26.2.2.18 | Umkehrung eines Pfads im ungerichteten Graphen — `UndirectedFinitePathReversal` | `Bd. 26 - Bäume.tex`:1509 | B23 nach Basis/Schritt. Aussage: ein endlicher Pfad besitzt einen Pfad gleicher Länge mit vertauschten Endpunkten. |
| 26.2.2.26 | Reduktion an einem gemeinsamen inneren Wegknoten — `FinitePathInteriorPairReduction` | `Bd. 26 - Bäume.tex`:2199 | B23 nach gerichteten Anfangs-/Endabschnitten und dem allgemeinen Folgensatz `FinitePathSplitRigidity` in B21. Aussage: zwei verschiedene Wege mit einem gemeinsamen inneren Knoten lassen sich auf ein kürzeres verschiedenes Wegpaar reduzieren. Die aktuelle Form setzt Ungerichtetheit voraus. Der Beweis benutzt davon allerdings nur `UndirectedGraphAccess`; eine separate Schwächung auf GraphStruct wäre möglich, dann sogar B22. Das ist eine zusätzliche mathematische Änderung und keine Voraussetzung der konservativen Verlagerung. |
| 26.2.2.27 | Intern disjunkte Wegbögen tragen einen endlichen Wegzyklus — `InternallyDisjointPathsFormCycleCore` | `Bd. 26 - Bäume.tex`:2524 | B23 nach Pfadumkehr und Abschnittsregeln. Intern disjunkte Wegbögen liefern einen Wegzykluskern auf ihrer Bildvereinigung. Der Beweis ruft `UndirectedFinitePathReversal` auf. Die ausführliche Zykluskern-Schreibweise beziehungsweise die lokale Makrodefinition `FinitePathCycleCore` muss dort verfügbar sein; die spätere Wald-/Azyklizitätsdefinition wird nicht vorausgesetzt. |
| 26.3.3.1 | Wurzelwege erzeugen Wege zwischen beliebigen Endpunkten — `RootPathsGivePairPath` | `Bd. 26 - Bäume.tex`:3295 | P2, B23 nach Umkehrung und `FinitePathTransportAlongWalk`, alternativ als Grundlemma für Zusammenhang am Anfang von B25. Aussage über beliebigen ungerichteten Graphen: Wege r→u und r→v liefern einen Weg u→v. Der Buchstabe r bezeichnet bloß den gemeinsamen Endpunkt; es wird keine verwurzelte Baumstruktur vorausgesetzt. 23 Beweiszeilen; schon Bestandteil der späteren Baumkriterien. |

`RootPathUniquenessTransfers` (26.3.3.2), `RootedTreeFromUniqueRootPaths` und die Wald-/Baumcharakterisierungen können in B26 zusammenbleiben: Sie bilden gerade das Kriterium aus eindeutigen Wurzelwegen für die Baumstruktur. Die Existenzverknüpfung `RootPathsGivePairPath` davor ist im Gegensatz dazu reine allgemeine Graphentheorie.

### C3. Korrektur früherer Zielorte, getrennt von neuen Kandidaten

Die folgenden **fünf** Sätze aus `tex/b26-migrated-tree-path-rules.tex` wurden bereits aus B27 verlagert. Sie werden deshalb nicht als fünf weitere bisher übersehene Auslagerungen gezählt. Nach Verlagerung der Wegfamilie und der gerichteten Operationen ist jedoch **B22 ihr richtiger gemeinsamer Zielort**:

| Aktuelle Nr. | Exakter Titel / ID | Quelle:Zeile | Ziel und Voraussetzungen |
| --- | --- | --- | --- |
| 26.2.2.28 | Index- und Knotendaten eines Pfadschritts — `B27PathStepData` | `tex/b26-migrated-tree-path-rules.tex`:5 | Korrektur des Zielorts nach B22; verwendet nur gerichtete Walk/Pfad-Typisierung und B10-Indizes. |
| 26.2.2.29 | Einführung eines gespeicherten Pfades — `B27SimplePathFamilyPairIntroduction` | `tex/b26-migrated-tree-path-rules.tex`:37 | Korrektur nach B22, unmittelbar bei der dortigen Wegfamilie. |
| 26.2.2.30 | Die Bestandteile eines gespeicherten Pfades — `B27SimplePathFamilyPairElimination` | `tex/b26-migrated-tree-path-rules.tex`:76 | Korrektur nach B22, unmittelbar bei der dortigen Wegfamilie. |
| 26.2.2.31 | Der Weg aus einem einzigen Knoten — `B27RootPathSingleton` | `tex/b26-migrated-tree-path-rules.tex`:128 | Korrektur nach B22; Nullweg aus dem Graphen {(0,r)}, benötigt keine Baumstruktur. |
| 26.2.2.32 | Ein erreichter Knoten führt über eine Kante weiter — `B27RootPathExtendExistence` | `tex/b26-migrated-tree-path-rules.tex`:165 | Korrektur nach B22; Anwendung der gerichteten Pfadfortsetzung. |

`tex/b26-migrated-tree-parent-systems.tex` und `tex/b26-migrated-tree-parent-proofs.tex` bleiben dagegen in B26: Die Rang-/Elternbedingungen werden dort als Modellkriterium für einen endlichen Wurzelbaum zusammengeführt und anschließend mit der Baumelternrelation identifiziert. Einzelne Träger- oder Höhenfolgen daraus wieder von der eigenen Definition zu trennen, würde den Modellbeweis ohne klaren Nutzen zerlegen.

## D. B27: Konkatenation endlicher Folgen statt erneuter Graphaufbau (P1)

Der existierende Abschnitt B21 „Verschobene Graphen endlicher Folgen“ (Haupttext:584; `ShiftedWordGraphDef`, `ShiftedWordGraphFunctional`) bietet den passenden Anknüpfungspunkt. Die neue allgemeine Operation kann ausdrücklich parametrisiert werden:

    m,n∈N, u:N_<m→A, v:N_<n→A
    C_{m,n}(u,v) := u ∪ {(m+j,v(j)) | j∈N_<n}.

Damit ist keinerlei Wortbegriff nötig. In B27 ergibt sich die bisherige Konkatenation durch m=|u|, n=|v|. Der ursprüngliche Einstieg des Wortbandes über Erzeugung/Anfügung bleibt davon unberührt.

### Zu verallgemeinernde Beweisgruppe

| Aktuelle Nr. | Exakter Titel / ID | Quelle:Zeile | Ziel und Voraussetzungen |
| --- | --- | --- | --- |
| 27.2.7.5 | Elementkriterium der Wortkonkatenation — `WordConcatenationMembership` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:646 | B21: Elementkriterium von C_{m,n}. Benötigt nur Vereinigung und `ShiftedWordGraphDef`; bisher7 Zeilen. |
| 27.2.7.6 | Disjunktheit der Indexblöcke einer Konkatenation — `WordConcatenationIndexBlocksDisjoint` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:705 | In der B21-Gruppenfassung direkte Verwendung von `PeanoTailAvoidsInitialSegmentLeft` aus B10: j∈N_<n ⇒ m+j∉N_<m. Kein neues arithmetisches Duplikat anlegen; bisher8 Zeilen Worttypisierung plus Anwendung. |
| 27.2.7.7 | Typisierung des Anfangsblocks einer Konkatenation — `WordConcatenationInitialGraphSubset` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:728 | B21: u⊆N_<(m+n)×A aus u:N_<m→A. Benötigt `FunctionGraphSubsetProduct`, `PeanoNatSegSubsetAddRight`, Produktmonotonie; bisher10 Zeilen. |
| 27.2.7.8 | Typisierung des verschobenen Konkatenationsblocks — `WordConcatenationShiftedGraphSubset` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:763 | B21: Typisierung eines verschobenen Punkts und seines Termbilds. Benötigt `PeanoNatSegShiftMembership` sowie `B27TermImageSubset` (3.18.1.5); bisher20 Zeilen, H2 davon10→5 allein durch bereits verfügbaren Termbildsatz möglich. |
| 27.2.7.9 | Totalität des Konkatenationsgraphen — `WordConcatenationGraphTotal` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:846 | B21: C_{m,n} ist total auf N_<(m+n). Benötigt Indexzerlegung `PeanoNatSegAddMembership` und Werte der beiden Folgen; bisher31 Zeilen. |
| 27.2.7.10 | Funktionalität des Konkatenationsgraphen — `WordConcatenationGraphFunctional` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:948 | B21: C_{m,n} ist funktional. Benötigt Funktionalität von u und des verschobenen Graphen (`ShiftedWordGraphFunctional` in B21) sowie Disjunktheit der Indexblöcke; bisher56 Zeilen. |
| 27.2.7.11 | Typisierung und Koordinaten der Konkatenation — `WordConcatenationTyping` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1135 | B21: C_{m,n}:N_<(m+n)→A, C(i)=u(i), C(m+j)=v(j). Benötigt die vorigen Typisierungs-/Totalitäts-/Funktionalitätssätze und `UniqueValuedGraphFunction`; bisher35 Zeilen. Der formale Graphfunktionsaufbau steht schon vor B21. |
| 27.2.7.14 | Kürzung bei festem Konkatenationsschnitt — `WordConcatenationFixedCutCancellation` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:1337 | B21: Gleichheit zweier zusammengesetzter Folgen am gleichen ersten Schnitt liefert Gleichheit beider Teilfolgen. Mit m,m′,n,n′ statt Wortlängen formulieren; Gleichheit des Gesamtdomänentyps und Kürzung der Summen liefern n=n′. Benötigt die Koordinatensätze, B10-Index-/Längeneindeutigkeit und `FunctionExtensionality`; bisher32 Zeilen. |

Die ersten sieben Hauptsätze haben **167 explizite Beweiszeilen**, mit dem Kürzungssatz **199**. Diese Zeilen verschwinden nicht aus dem Gesamtwerk; sie erhalten einen allgemein verwendbaren Ort. In B27 reichen anschließend kurze Spezialisierungen durch `FiniteWordTypingAtLength` und die natürliche Wortlänge. Auch B26 kann die allgemeinen Folgenbausteine nutzen, bevor B27 beginnt.

### Bewusst in B27 verbleibende Verbindung

- 27.2.7.1–4 (`WordAppendOccurrenceEquation`, `WordAppendOccurrenceFresh`, `WordAppendFiniteByAdjunction`, `WordModelSuccessorConcatenation`): Verbindung mit Buchstabenwort und primitiver Anfügung. Die allgemeine Punktadjunktion ist bereits früher vorhanden; diese Sätze stellen die Wortverbindung her.
- 27.2.7.12–13: Abschluss der erzeugten Wortmenge und Gleichung für die **Wortlänge** sind kurze Anwendungen der allgemeinen Folgentypisierung; sie dürfen als solche bleiben.
- 27.2.7.16–17: Verträglichkeit mit dem primitiven Nachfolger und Assoziativität aus W0–W3. Den gewünschten axiomatischen Beweis nicht durch einen erneuten vollständigen Koordinatenbeweis ersetzen. Ein optionaler allgemeiner Folgen-Assoziativitätssatz wäre ein eigenständiger Ausbau von B21, keine Voraussetzung der hier vorgeschlagenen Verlagerung.
- Rumpf-/Endbuchstabenfunktionen 27.2.8.6–17 werden aus der eindeutigen **Wortzerlegung** aufgebaut. Allgemeine Einschränkung und Wiedergewinnung einer endlichen Folge stehen bereits in B21; die in B27 gewählte axiomatische Eliminator-Sicht bleibt inhaltlich sinnvoll.

## E. B27: gemeinsame Stufe (P2)

| Aktuelle Nr. | Exakter Titel / ID | Quelle:Zeile | Ziel und Voraussetzungen |
| --- | --- | --- | --- |
| 27.3.2.11 | Gemeinsame Baumstufe — `TreeCommonStage` | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`:3055 | B21 nach `SubsetSequenceNesting` (21.4.3.2), Abschnitt „Wachsende Folgen von Mengen“, Haupttext:1123ff. Allgemeine Fassung: D:N→P(M), ∀j D(j)⊆D(j+1), ∃m∈N x∈D(m), ∃n∈N y∈D(n) ⇒ ∃q∈N x,y∈D(q). Benötigt `PeanoOrderComparison` und `SubsetSequenceNesting`, keine Bäume. Der jetzige Beweis hat31 Zeilen (8+8+15) und ist vollständig dieser allgemeinen Vergleichsargumentation gewidmet. B27 belegt nur noch, dass TreeStage_A eine wachsende Folge mit dem betreffenden Baumträger als Vereinigung ist. |

Dies ist eine natürliche Verallgemeinerung, keine rein formale Umbenennung. Sie hat eine deutlich kleinere Begriffsfläche als eine allgemeine Theorie aller erzeugten Strukturen. Im aktuellen Werk ist der sichere Gewinn die Verkürzung des Baumstufenbeweises; weitere Anwendungen wurden hier nicht behauptet, ohne sie nachgewiesen zu haben.

## F. B22–B25: allgemeine Mengentechnik und echte Spezialisierungen

- **B22 22.2.2.1–2 und 22.2.3.2/4:** Die ausführlichen Elementkriterien von Nachbarschaft, Umkehrrelation und induzierter Kantenrelation verwenden nur Aussonderung, Produkt- und Schnittmitgliedschaft. Ihre **Beweise** können viel direkter aus den bestehenden B3-Kriterien geführt werden. Die graphischen Definitionen und Aussagen dürfen in B22 bleiben. Ein neues allgemeines „Graph-Nachbarschaftslemma“ in B3 wäre keine zusätzliche mathematische Grundlage. Orte: `DirectedOutNeighborhoodMembership` Haupttext:109; `DirectedInNeighborhoodMembership`:178; `DirectedReverseEdgeMembership`:299; `DirectedInducedEdgeMembership`:398.
- **B22 22.2.1.1–2:** Graphrelation-/Endpunkttypisierung könnten unmittelbar zur bereits in B3 eingeführten Graphdefinition gestellt werden. Es sind jedoch nur zwei bzw. fünf Beweiszeilen und sie eröffnen bewusst den Graphenband. Deshalb geringe Priorität; kein erforderlicher Umzug. Eine allgemeine Relationsumkehr für beliebige Relationen wäre eine mögliche Erweiterung von B3, in der geprüften B22-Gruppe aber nicht als mehrfach benötigte neue Theorie belegt.
- **B23:** `UndirectedNeighborhoodMembership` 23.2.2.1 setzt die B22-Ausnachbarschaftsregel ein; `UndirectedInducedSubgraph` 23.3.1.2 benutzt bereits `DirectedInducedSubgraph`. Der Mehrinhalt ist jeweils die Symmetrie. Keine bloße Wiederholung des gesamten früheren Beweises.
- **B24:** `SimpleUndirectedInducedSubgraph` 24.2.2.1 benutzt den B23-Satz und ergänzt Schleifenfreiheit. Das ist die passende strukturelle Spezialisierung.
- **B25:** Die beiden Theoreme sind reine Zugriffssätze auf den gerade definierten Zusammenhang. Es gibt dort keinen versteckten arithmetischen oder mengentheoretischen Beweisblock. Der Band wirkt kurz, weil die allgemeinen Pfadoperationen erst in B26 stehen; ein Aufbau dieser Grundlagen in B22/B23 behebt den logischen Ort, ohne B25 künstlich mit Fremdstoff zu füllen.

## G. Weitere Grenzfälle in B27

1. Die drei Konstruktionen kleinster abgeschlossener Mengen (Worterzeugung, Wortrekursionsgraph, Baumrekursionsgraph) bieten einen **wiederkehrenden allgemeinen Beweisgedanken**. Ein Satz über die kleinste durch Mengenschnitt bestimmte abgeschlossene Teilmenge könnte in B3 oder bei expliziten Operationen in B5/B7 liegen. Die Anwendungen müssten jedoch weiterhin nachweisen, dass ihr jeweiliger Abschluss unter Schnitt erhalten bleibt. Das ist ein möglicher größerer Ausbau (P3), nicht so unmittelbar ergiebig wie die konkrete Folgenkonkatenation.
2. `WordStructurePairInjective` 27.2.6.3, `tex/b27-word-structure-consequences.tex`:21, könnte eine allgemeine Produkt-Injektivitätsregel motivieren. Die zwölf Zeilen sind eine transparente Anwendung von W2 und Paarprojektionen; kein vorrangiger Auslagerungsfall.
3. `BinaryTreeRecursionFilteredFiberUnique` 27.3.4.12, `tex/b27-tree-axiomatic-recursion.tex`:271: Die allgemeine Faserfiltertheorie steht bereits in B7. Alte Zeilen9–12 durch `WordRecursionFilterOwnFiber{5,8}` (7.3.1.25) ersetzen ergibt17→14 Zeilen. Das ist Wiederverwendung, keine weitere Auslagerung.
4. Adresswege und Positionsgraphen in B27 sind Anwendungen der allgemeinen Pfad-/Elternregeln. Nach deren richtigem Ort B22/B26 bleiben die Nachweise für binäre Wortadressen und Klammerungsbäume in B27. Blattwörter, Klammerungsrelationen und Auswertungsrekursionen in Kapitel5 benötigen die Verbindung von Wort- und Baummodell; Kapitel6 die zugehörigen Strukturaxiome/Isomorphismen. Dort wurde kein zusätzlicher ähnlich klar abtrennbarer Grundlagenblock entdeckt.

## Empfohlene Reihenfolge bei einer späteren Umsetzung

1. Die fünf B26-Arithmetiksätze nach B10; Transitivitätsabhängigkeit beachten.
2. Die reinen B26-Folgengrundlagen und die generalisierte B27-Konkatenation nach B21, nach vorhandener Index-/Graphfolgenbasis. Gemeinsame Stufe anschließend bei wachsenden Mengenfolgen.
3. Wegfamilie samt Definitionen, gerichtete Operationen und korrigierter Zielort der fünf schon migrierten Pfadregeln nach B22.
4. Umkehrdefinition und Umkehr-/Zyklusgruppe nach B23. Erst dann die Quellaufrufe in B26 auf die früheren Ergebnisse umstellen.
5. In B27 die Wort-Konkatenation als Instanz anschließen und die bereits gewünschte axiomatische Beweisfolge beibehalten.

Die unter C vorgeschlagene Zerlegung ist topologisch möglich: Der derzeitige B26-Vorbau bis zum Beginn der Wälder hat keine Abhängigkeit von den späteren Wald-/Baumdefinitionen. Die ungerichtete Gruppe darf auf die gerichtete verweisen; der gerichtete Teil braucht keine ungerichteten Ergebnisse. Bei einer schwächeren Graphfassung von `FinitePathInteriorPairReduction` wäre die Abhängigkeit nochmals gesondert zu prüfen. Die vorherige Liste von47 Auslagerungen ist hier nicht erneut als neue Fundliste gezählt.
