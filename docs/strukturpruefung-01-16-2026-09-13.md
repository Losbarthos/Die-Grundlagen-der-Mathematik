# Strukturprüfung B01–B16 und allgemeine Abschlusskerne aus B27

Stand: 13.09.2026. Nur Review; keine Manuskriptänderungen oder Builds. Grundlage sind die aktuellen aktiven Quellen samt Includes, die Register und die bereinigte Inventur critical-inventory.json (ohne separat registrierte Hilfsteile). Die Tabelle dokumentiert eine Strukturprüfung von Aussagen, Definitionen und Abhängigkeiten; sie ist keine vollständige zeilenweise Beweiskorrektheitsprüfung.

## Ergebnis und Priorität

Die Wortnotation ist kein ausreichender Grund, einen Satz in B27 zu lassen. Es gibt einen gemeinsamen mengenlogischen Kern hinter Worterzeugung, natürlicher Rekursion und Baumrekursion. Ebenso enthält B08 noch reine Mengensätze und Ergebnisse, die nur Injektivität oder nur Surjektivität voraussetzen. Die stärksten Pakete sind:

| Priorität | Paket | Empfehlung |
|---|---|---|
| Hoch | K1: kleinste abgeschlossene Menge | Allgemeines Erzeugungsschema in B03; die Konstruktionen in B10/B27 als Anwendungen |
| Hoch | K2: Minimalität und Faserfilter | Allgemeines Faserlemma in B07; konstruktorspezifische Zulässigkeitsbeweise bleiben B27 |
| Hoch | K3: sieben Quantoren-/Eindeutigkeitsregeln aus B07 | Nach B02; beschränkte Quantorenschreibweise steht bereits in B01 |
| Hoch | K4: Funktion aus eindeutigem Relationswert | Nach B05; B07 braucht nur die Anwendung |
| Hoch | K5: Kernfamilien und Schichtzerlegung aus B08 | B03-Intervalltheorie wiederverwenden bzw. dort ergänzen |
| Hoch | K6/K7: Kompositionsfaktoren und Potenzmengenabbildung | Allgemeine Injektivitätsaussagen nach B06, Surjektivitätsaussagen nach B07 |
| Mittel | K8: elementare Abbildungen und Neutralität | Definition, Typ und Auswertung nach B05; Klassifikation in B06–B08 behalten |
| Mittel | K9: Rechtsinverse ist injektiv | Allgemeiner Satz vor dem Auswahlprinzip; B09 nur Anwendung |
| Hoch, kleiner Umfang | K10: Dualität der Extrema, Inklusionsordnung | B13/B14 → B12; Voraussetzungen liegen vollständig vor |

Nicht jedes Paket verlangt neue Definitionen. Besonders K5 sollte vorhandene allgemeine Sätze nutzen, statt unter neuer Notation nochmals dieselbe Theorie anzulegen.

## K1 — Allgemeines Erzeugungsschema nach B03

Eine ausreichend allgemeine, aber noch elementare Formulierung lautet:

Seien E eine Menge, S⊆E und R⊆P(E)×E. Ein C⊆E heiße abgeschlossen, wenn S⊆C gilt und für alle D⊆E und x∈E aus (D,x)∈R und D⊆C folgt, dass x∈C. Setze

    𝒞 = {C∈P(E) | S⊆C und ∀(D,x)∈R (D⊆C ⇒ x∈C)},
    K = ⋂𝒞.

Dann gilt: E∈𝒞, also 𝒞≠∅; K⊆E; S⊆K; K∈𝒞; für jedes C∈𝒞 gilt K⊆C. Ferner gilt die Induktion über K: Wenn P auf S gilt und für jede Regel (D,x)∈R mit D⊆K aus ∀d∈D P(d) auch P(x) folgt, dann gilt ∀x∈K P(x).

Beweis: Alle Familienglieder enthalten die Ausgangselemente. Sind die Prämissen D in ihrem Durchschnitt, liegen sie in jedem Familienglied und damit auch die Folgerung x. Für die Induktion ist U={x∈K | P(x)} wieder abgeschlossen; Minimalität ergibt K⊆U. Das ist mengenlogisch und benötigt weder natürliche Zahlen noch Endlichkeit, Funktionen, Halbordnungen oder Wortaxiome.

| Aktueller Satz | ID | Quelle | Allgemeiner Anteil |
|---|---|---|---|
| 27.2.1.4 Elementkriterium der abgeschlossenen Mengen | WordGenerationFamilyMembership | tex/b27-word-generated-set.tex:133 | Aussonderung einer Abschlussfamilie |
| 27.2.1.5 Der Umgebungsbereich ist eine abgeschlossene Menge | WordGenerationUniverseMember | dieselbe Datei:182 | E ist abgeschlossen |
| 27.2.1.6 Die Familie abgeschlossener Mengen ist nicht leer | WordGenerationFamilyNonempty | :201 | E ist ein Familienzeuge |
| 27.2.1.7 Elementkriterium des erzeugten Wortbereichs | GeneratedWordMembership | :228 | Elementkriterium des nichtleeren Durchschnitts |
| 27.2.1.8 Jede abgeschlossene Menge enthält alle Wörter | FiniteWordSetGenerationLeast | :249 | Durchschnitt ist Teilmenge jedes Familienglieds |
| 27.2.1.12 Das leere Wort | GeneratedWordEmpty | :300 | Ausgangselement gehört zu K |
| 27.2.1.13 Wörter bleiben unter dem Erzeugungsschritt abgeschlossen | GeneratedWordClosed | :318 | Regelschluss in K |
| 27.2.1.14 Die Wortmenge ist eine abgeschlossene Menge | FiniteWordSetGenerationClosed | :345 | K∈𝒞 |
| 27.2.1.15 Minimalität der erzeugten Wortmenge | GeneratedWordMinimality | :361 | Minimalität unter expliziten Abschlussvoraussetzungen |
| 27.2.1.16 Induktion für erzeugte Wörter | GeneratedWordInduction | :386 | Induktion aus Minimalität |
| 27.2.1.17 Induktionsregel für erzeugte Wörter | GeneratedWordInductionRule | :437 | Dieselbe Induktion als Regel mit Eigenvariablen |
| 27.2.6.12 Kleinster abgeschlossener Rekursionsgraph | WordStructureRecursionLeastGraph | tex/b27-word-axiomatic-recursion.tex:101 | Existenz/Abschluss/Minimalität in W×X |
| 27.3.4.11 Existenz des kleinsten abgeschlossenen Baumgraphen | BinaryTreeLeastClosedGraphExists | tex/b27-tree-axiomatic-recursion.tex:122 | Derselbe Schluss für ein- und zweigliedrige Prämissen |
| 10.4.3.9 Rekursionskern ist kleinster rekursionsadmissibler Graphkandidat | RecCoreLeastAdmissible | Bd. 10 - Natürliche Zahlen.tex:5322 | Zusammenfassung desselben Erzeugungskerns |

Zum B10-Paket gehören die vorausgehenden Aussagen 10.4.3.1 (voller Produktraum, :4838), 10.4.3.3–8 (Charakterisierung, Minimalität, Träger, Startpaar, Abschluss und Admissibilität, :5030–5299); sie würden auf das allgemeine Schema verweisen. Die Aussage 10.4.3.9 lautet unter m₀∈M und f:M→M: G⊆N×M, (0,m₀)∈G, AdmRec(G) und ∀H(AdmRec(H)⇒G⊆H).

Die drei B27-Instanzen sind konkret:

- Worterzeugung: E=FinSub(N×A), S={∅}; die Regeln lauten ({w},J(w,a)) mit w∈E und a∈A. Die Typisierung und Endlichkeit von J(w,a)=w∪{(#w,a)} bleiben B27.
- Wortrekursionsgraph: E=W×X, S={(e,x₀)}; aus {(u,x)} entsteht (s(u,a),r(x,a)). Hier braucht die Abschlusskonstruktion nur Typisierung von e,s,r. Nicht benötigt werden W1, W2 oder W3.
- Baumrekursionsgraph: E=T×X; S besteht aus (ℓ(a),f(a)); aus {(u,x),(v,y)} entsteht (k(u,v),g(x,y)). Für die kleinste abgeschlossene Menge sind Trennung und Injektivität der Konstruktoren sowie Bauminduktion noch nicht nötig.

Die natürliche Rekursion benutzt E=N×M, S={(0,m₀)} und ({(n,x)},(n+1,f(x))). Daher hat das allgemeine Ergebnis bereits deutlich vor B27 einen konkreten Einsatz.

Vorhandene Grundlagen: B03 Aussonderung und ihr Teilmengensatz (:933), Durchschnittsminimalität (:2238 ff.), Elementkriterium des nichtleeren Familiendurchschnitts (:2295 ff.), Potenzmenge (:5147 ff.), kartesisches Produkt; SubsetIntroductionRule. Zielplatz ist entsprechend spät in B03, nach Potenzmenge und Produkt.

Risiken und Grenzen: Nicht beliebige Prädikate C(H) sind unter Durchschnitten abgeschlossen. Die positive Regelform mit D⊆C ist die entscheidende Hypothese. Die Familie muss vor Verwendung ihres Durchschnitts als nicht leer bewiesen werden. Für einen induktiven Bereich ohne vorgegebenen Umgebungsträger muss erst ein geeigneter Träger bereitgestellt werden; die unbeschränkte Anfangskonstruktion von N darf nicht kommentarlos durch diese beschränkte Variante ersetzt werden. Die hier angegebene Anwendung auf den Rekursionskern hat dieses Problem nicht. Die konkrete und abstrakte Wortinduktionsregel können als kurze, gut lesbare Instanzen in B27 bestehen bleiben.

## K2 — Minimalität plus Faserfilter nach B07

27.3.4.12 „Ein zulässiger Faserfilter erzwingt einen einzigen Wert“, ID BinaryTreeRecursionFilteredFiberUnique, tex/b27-tree-axiomatic-recursion.tex:271, lautet:

    M(G), C(Φ^{T,X}_{t,c}(G)), c∈X, (t,c)∈G
    ⇒ ∃!x∈X (t,x)∈G.

M(G) bedeutet hier, dass G ein kleinstes C-abgeschlossenes Baumgraphengebilde ist. Der Beweis verwendet keine Baumaxiome. Seine allgemeine Aussage ist:

    G⊆U×V, K₀⊆U×V,
    ∀H∈𝒞 (G⊆H), Φ^{U,V}_{t,c}(K₀)∈𝒞,
    c∈V, (t,c)∈G
    ⇒ ∃!x∈V (t,x)∈G.

Beweis: Minimalität liefert G⊆Φ(K₀). Für jeden zweiten Zeugen (t,z)∈G folgt Zugehörigkeit zum Filter und damit z=c. Der vorhandene Zeuge c liefert die eindeutige Existenz. G selbst muss für diesen Schluss nicht zusätzlich als Familienglied vorausgesetzt werden.

K₀ ist absichtlich allgemein: Beim Wort-Anfangswert wird der volle Produktraum gefiltert, beim Wort-Nachfolger und Baumargument der kleinste Graph selbst. Damit trägt ein Satz alle Varianten.

Vorhandene Grundlagen in B07, nicht erneut auszulagern: WordRecursionFilterSubset (7.3.1.23), WordRecursionFilterMembership (7.3.1.24) und WordRecursionFilterOwnFiber (7.3.1.25), tex/b07-migrated-fiber-filter.tex:27/57/103. Die eindeutige Existenz aus einem festen Zeugen steht bereits in B02, WordUniqueExistenceFromWitness.

Weitere Anwendungen:

- 27.2.6.13 „Eindeutiger Anfangswert des kleinsten Graphen“, WordStructureRecursionBaseFiber, tex/b27-word-axiomatic-recursion.tex:146: nur der anschließende Minimalitäts-/Faserschluss wird allgemein; die Zulässigkeit des Filters braucht die Trennung s(u,a)≠e.
- 27.2.6.14 „Eindeutige Werte bleiben beim Anfügen eindeutig“, WordStructureRecursionStepFiber, dieselbe Datei:188: die Filterzulässigkeit braucht zusätzlich die Injektivität des Anfügens; dieser Teil bleibt B27.
- 10.4.3.10 und 10.4.3.12, „Die Nullstufe des Rekursionskerns ist festgelegt“ (:5404) und „Die Nachfolgerstufe des Rekursionskerns ist durch die Vorstufe festgelegt“ (:5739), verwenden dieselbe Schrankenidee. Die B10-Schreibweise des Filters benutzt die äquivalente Implikation y=n+1⇒d=f(a). RecCoreStageBarrier (10.4.3.13, :5803) fasst diese Resultate nur zusammen und ist keine zusätzliche unabhängige Auslagerung.

Grenze: Aus Minimalität allein folgt keine eindeutige Faser. Die Zulässigkeit genau des vorgeschriebenen Filters und ein tatsächlicher Faserzeuge sind nötig. Die Gesamt-Rekursionstheoreme für Wörter/Bäume bleiben an ihrem sachlichen Ort.

## K3 — Logische Normalisierung aus B07 nach B02

Alle folgenden Aussagen stehen in tex/b07-quotient-normalization.tex. Sie enthalten keinerlei Funktions-, Surjektions- oder Quotientenvoraussetzung. B01 führt beschränkte Quantoren bereits ab :999 als Schreibkonvention ein. Daher ist B02 unmittelbar möglich; B03 muss nicht abgewartet werden.

| Satz / genauer Titel | ID | Zeile | Aussage |
|---|---|---:|---|
| 7.3.5.1 Beschränkte Existenzquantoren über ein Paar | BoundedPairExistsGuard | 12 | ∃a∈A∃b∈B H(a,b) ↔ ∃a∃b((a∈A∧b∈B)∧H(a,b)) |
| 7.3.5.2 Vier Existenzquantoren mit paarweisen Trägerbedingungen | BoundedFourExistsGuard | 59 | Vier beschränkte Existenzquantoren werden als vier unbeschränkte Quantoren mit paarweisen Trägerbedingungen geschrieben |
| 7.3.5.3 Vier Existenzquantoren nach Trägern gruppieren | BoundedFourExistsGroupedGuard | 118 | Dasselbe bei Quantorreihenfolge a,c∈A und b,d∈B; Umordnung in a,b,c,d |
| 7.3.5.4 Zusatzbedingung einer Paarrepräsentation | BoundedPairExistsGuardWithCondition | 177 | ∃a∈A∃b∈B(H∧K∧L) ↔ ∃a∃b((a∈A∧b∈B∧K)∧H∧L) |
| 7.3.5.5 Beschränkte Allquantoren über ein Paar | BoundedPairForallGuard | 236 | ∀a∈A∀b∈B H(a,b) ↔ ∀a∀b((a∈A∧b∈B)⇒H(a,b)) |
| 7.3.5.6 Eindeutige Existenz bei punktweise äquivalenten Prädikaten | UniqueExistenceUnderPointwiseEquivalence | 289 | ∀z(P(z)↔Q(z)), ∃!z P(z) ⇒ ∃!z Q(z) |
| 7.3.5.7 Prädikatwechsel bei eindeutiger Existenz mit fester Zusatzbedingung | UniqueExistenceUnderEquivalentConjuncts | 337 | ∀z(P(z)↔Q(z)), ∃!z(R(z)∧P(z)) ⇒ ∃!z(R(z)∧Q(z)) |

Bereits vorhandene verwandte Sätze: B02 2.10.8.6 „Invarianz unter prädikatenlogischer Äquivalenz“ für Höchstens-eins (:4651), 2.10.9.5 „Zerlegung der eindeutigen Existenz“ (:4729) und die üblichen Quantoren-/Konjunktionsregeln. 7.3.5.7 ist ein Korollar von .6 mit P′=R∧P und Q′=R∧Q. Keine neue inhaltliche Theorie nötig; besser ein gemeinsamer Logikblock. Die späteren echten Faser-/Faktorabbildungssätze 7.3.5.8–11 und .13–14 bleiben sachlich B07.

## K4 — Funktionen aus eindeutig bestimmten Werten nach B05

7.3.5.12 „Funktion aus einer Relation mit eindeutigem Wert“, ID UniqueRelationFunctionExists, Bd. 07 - Surjektive Funktionen.tex:2113:

    ∀u∈Q ∃!z∈B R(u,z)
    ⇒ ∃F(F:Q→B ∧ ∀u∈Q∀z∈B(R(u,z)⇒F(u)=z)).

Das ist ein allgemeiner Funktionserzeugungssatz. Die aktuelle Ableitung (44 Zeilen) sondert den Graphen im Produkt Q×B aus, weist eindeutige Werte nach und wertet ihn aus. Sie braucht weder Surjektivität noch das Auswahlaxiom. B05 hat bereits 5.2.6.1 „Graph mit eindeutigen Werten ist eine Funktion“, UniqueValuedGraphFunction, :1682. Danach ist der richtige Ort.

Abhängigkeit: Die aktuelle konkrete Graphschreibweise verwendet Projektionen und ProductComprehensionMembership, die derzeit erst B07 stehen. Für eine unveränderte Verschiebung müssen diese Grundlagen wie in K8 früher stehen. Alternativ bildet man schon in B05 den Graphen mittels des Prädikats ∃u∈Q∃z∈B(p=(u,z)∧R(u,z)); Paarinjektivität und Aussonderung aus B03 reichen. Das ist eine echte, auflösbare Darstellungsabhängigkeit und kein sachlicher Surjektivitätsbedarf. Das Ergebnis ist eine Ergänzung zu UniqueValuedGraphFunction, kein wörtliches Duplikat: Es startet bei einem Prädikat und liefert eine Funktion samt Auswertungsregel.

## K5 — Reine Mengenkerne aus B08 nach B03

Quelle aller folgenden Sätze: Bd. 08 - Bijektive Funktionen.tex. Die Datei erläutert selbst vor :2883, dass CoreFamily(P,A) lediglich das boolesche Intervall I[P,P∪A] hervorhebt.

| Satz / Titel | ID | Zeile | Empfehlung |
|---|---|---:|---|
| 8.3.6.2 Kernfamilien sind boolesche Intervalle | CoreFamilyBooleanInterval | 2891 | Reiner Notationsanschluss; B03 oder kurze lokale Aliasgleichung ohne neues Grundtheorem |
| 8.3.6.3 Elementkriterium einer Kernfamilie | CoreFamilyMembership | 2910 | P⊆H⊆P∪A; vorhandenes B03-Intervallkriterium verwenden |
| 8.3.6.4 Jede Kernfamilie liegt in der Potenzmenge ihres Trägers | CoreFamilySubsetPowerset | 2931 | Unmittelbare B03-Instanz; kein Bijektionsgehalt |
| 8.3.6.5 Zerlegung einer Kernfamilie an einem adjungierten Punkt | CoreFamilyAdjoinedSplit | 2946 | Allgemeine disjunkte Intervallzerlegung nach B03 |
| 8.3.6.8 Rest einer Kernfamilie liegt in der variablen Schicht | CoreFamilyRemainder | 3234 | Allgemeines Differenzlemma aus B03 verwenden |
| 8.3.6.15 Zerlegung einer Menge in zwei Schichten | LayerSetDecomposition | 3921 | Allgemeine Distributivitätsanwendung in B03; keine spezielle Schichttheorie erforderlich |

Für den wichtigsten neuen Inhalt .5 lautet die allgemeine Fassung mit L⊆U und c∉U:

    I[L,U∪{c}] = I[L,U] ∪ I[L∪{c},U∪{c}],
    I[L,U] ∩ I[L∪{c},U∪{c}] = ∅.

Beweis durch die Fälle c∈H/c∉H. Der B08-Satz ist L=P, U=P∪A. Vorhanden sind BooleanSetIntervalMembership (3.16.4.1, B03:5328), BooleanSetIntervalCoordinateCorrespondence (3.16.4.3, :5390), BooleanSetIntervalCoreEnvelope (3.16.4.4, :5533), außerdem alle Differenz- und Adjunktionsregeln. Keine Voraussetzung fehlt.

Bei .8 ist sogar die aktuelle Prämisse P∩A=∅ unnötig: Schon H⊆P∪A impliziert H\P⊆A. Die Ableitung benutzt die Disjunktheitsprämisse nicht. Der allgemeine Mengenbeweis: x∈H\P liefert x∈P∪A und x∉P, also x∈A. Nicht als neues Kernfamilienlemma verankern.

Bei .15 reicht X⊆A∪D für X=(X∩A)∪(X∩D); der vorhandene Beweis verwendet ausschließlich X∩(A∪D)=X und Distributivität aus B03.

Die tatsächlichen Kerntransporte, Rücktransporte und bijektiven Schichtfortsetzungen bleiben B08. Ihre Mengenvorbereitung kann auf B03 verweisen. Ein bloßes vollständiges Verschieben des gesamten Abschnitts wäre falsch.

## K6 — Allgemeine Aussagen über Kompositionsfaktoren

Quelle: Bd. 08 - Bijektive Funktionen.tex.

| Aktuelle Sätze | IDs | Zeilen | Allgemeiner Satz / Ziel |
|---|---|---|---|
| 8.3.4.8 Punktweises Injektivitätskriterium des inneren Faktors; 8.3.4.11 Injektivität des inneren Faktors | BijectiveCompositionInnerInjectiveCriterion; BijectiveCompositionInnerInjective | 1301; 1466 | F:A→B, G:B→C, G∘F injektiv ⇒ F injektiv. B06 |
| 8.3.4.9 Punktweises Surjektivitätskriterium des äußeren Faktors; 8.3.4.12 Surjektivität des äußeren Faktors | BijectiveCompositionOuterSurjectiveCriterion; BijectiveCompositionOuterSurjective | 1342; 1500 | F:A→B, G:B→C, G∘F surjektiv ⇒ G surjektiv. B07 |
| 8.3.4.10 Punktweises Injektivitätskriterium des äußeren Faktors | BijectiveCompositionOuterInjectiveCriterion | 1387 | F:A↠B, G:B→C, G∘F injektiv ⇒ G injektiv. B07, weil F surjektiv vorkommt |

Der erste Beweis braucht nur die Gleichheit G(F(x))=G(F(y)) und Injektivität der Komposition. Der zweite wählt einen Kompositionszeugen x und setzt b=F(x). Der dritte hebt zwei Punkte aus B über die Surjektivität von F nach A und verwendet dort die Injektivität der Komposition. Kein Beweis benötigt Bijektivität. B05 enthält Funktionstyp und Auswertung der Komposition; B06 bzw. B07 enthalten die erforderlichen Klassifikationen. Alte IDs mit Bijective im Namen sollten nur Korollare bleiben; die allgemeineren Fassungen erhalten passende neue IDs. 8.3.4.13 „Bijektivität des äußeren Faktors“ kann anschließend als Kombination in B08 stehen bleiben.

## K7 — Reflexion an Einermengen vor dem Bijektionsband

Quelle: Bd. 08 - Bijektive Funktionen.tex.

| Sätze | IDs | Zeilen | Ziel |
|---|---|---|---|
| 8.3.5.4 Injektivität wird von der induzierten Potenzmengenabbildung reflektiert; 8.3.5.5 Injektivität der induzierten Potenzmengenabbildung erzwingt Injektivität | PowerMapInjectivityPointwiseReflection; PowerMapInjectiveReflectsInjectivity | 1792; 1856 | B06 |
| 8.3.5.6 Surjektivität wird von der induzierten Potenzmengenabbildung reflektiert; 8.3.5.7 Surjektivität der induzierten Potenzmengenabbildung erzwingt Surjektivität | PowerMapSurjectivityPointwiseReflection; PowerMapSurjectiveReflectsSurjectivity | 1877; 1929 | B07 |
| 8.3.5.11 Eingeschränkte Injektivität wird an Einermengen reflektiert; 8.3.5.12 Eingeschränkte Injektivität erzwingt Injektivität der Grundabbildung | RestrictedPowerMapInjectivityPointwiseReflection; RestrictedPowerMapInjectiveReflectsInjectivity | 2284; 2402 | Allgemeiner Familienkern in B06, konkrete Restfamilie als Korollar |
| 8.3.5.13 Eingeschränkte Surjektivität wird an Einermengen reflektiert; 8.3.5.14 Eingeschränkte Surjektivität erzwingt Surjektivität der Grundabbildung | RestrictedPowerMapSurjectivityPointwiseReflection; RestrictedPowerMapSurjectiveReflectsSurjectivity | 2429; 2506 | Allgemeiner Familienkern in B07, konkrete Restfamilie als Korollar |

Die unbeschränkten Aussagen lauten unter F:A→B: PowMap(F) injektiv ⇒ F injektiv bzw. PowMap(F) surjektiv ⇒ F surjektiv. PowMap ist bereits B05 definiert und typisiert (5.3.3.13–14, :3771/:3783).

Der gemeinsame Kern der eingeschränkten Variante vermeidet sogar die spezielle Verwendung derselben Ausschlussfamilie C auf beiden Seiten:

- Sei 𝒜⊆P(A), seien alle {a} mit a∈A in 𝒜, und sei H:𝒜→𝒝 injektiv mit H(X)=F[X]. Dann ist F injektiv: F(a)=F(b) ergibt H({a})={F(a)}={F(b)}=H({b}), also {a}={b} und a=b.
- Sei H:𝒜↠𝒝 mit H(X)=F[X] und 𝒜⊆P(A). Wenn jedes {b}, b∈B, in 𝒝 liegt, ist F:A→B surjektiv: Ein Urbild X von {b} liefert einen a∈X mit F(a)=b.

Diese Voraussetzungen enthalten weder Bijektionen noch Kardinalzahlen. Die aktuellen Restfamilien P(A)\C und P(B)\C sind Spezialfälle. Die kombinierten Bijektivitätskriterien .8, .10 und .15 können B08 bleiben. Die Nummer .10 ist die ausdrücklich auf C zugeschnittene Charakterisierung und wird hier nicht pauschal nach vorne verlagert.

## K8 — Elementare Abbildungen vor ihrer Klassifikation

Ein kohärentes kleines Grundlagenpaket in B05 ist didaktisch sinnvoller als verstreute Erstdefinitionen. Keine einzelne Auswertungszeile muss dafür als eigener neuer Hauptsatz vervielfacht werden.

| Vorhandene Stelle | Quelle | Inhalt |
|---|---|---|
| 6.3.3.1 Inklusionsabbildung von A nach B; 6.3.3.3 Grundgleichung der Inklusionsabbildung | Bd. 06 - Injektive Funktionen.tex:857/:879; Definition :840, InclusionMapDef | A⊆B ⇒ ι:A→B und x∈A ⇒ ι(x)=x |
| 6.3.4.2 Werte der Inklusionskomposition liegen im kleineren Ziel; 6.3.4.3 Auswertung einer Inklusionskomposition | dieselbe Datei:966/:994; .3 ID InclusionCompositionValue | Typisierung/Auswertung der Komposition ohne Injektivitätsbedarf |
| 6.3.4.7, unbetitelt | dieselbe Datei:1069 | F:B→C, A⊆B ⇒ F↾A=F∘ι(A,B) |
| 7.3.1.1/3 und 7.3.1.5/7, Projektion auf die erste/zweite Komponente und jeweilige Grundgleichung | Bd. 07 - Surjektive Funktionen.tex:903/:923/:971/:991; Definitionen :886/:954, FirstProjectionDef/SecondProjectionDef | π₁:A×B→A, π₂:A×B→B und ihre Werte |
| 7.3.1.9 Rekonstruktion aus Projektionen; 7.3.1.10 Element des Produkts als Paar | dieselbe Datei:1022/:1045 | p=(π₁p,π₂p) für p∈A×B |
| 8.3.1.1 Identitätsfunktion; 8.3.1.3 Identitätsfunktion auf A | Bd. 08 - Bijektive Funktionen.tex:303/:325; IdA, Definition IdentityFunctionDef :290 | Id:A→A und Id(x)=x |
| 8.3.4.2 Linksneutralität; 8.3.4.3 Rechtsneutralität | dieselbe Datei:1070/:1101; FunctionLeftIdentity/FunctionRightIdentity | F:A→B ⇒ Id_B∘F=F und F∘Id_A=F |

Die kleineren Träger-/Projektionsfolgen 7.3.1.12–17 gehören bei einer solchen Umordnung unmittelbar zu den Projektionen. Keine Nichtleerheitsannahme wird für die Funktionstypen gebraucht, auch leere Produkte funktionieren. Nichtleerheit braucht erst die Surjektivität der Projektionen; 7.3.1.18–21 bleibt B07. Ebenso bleiben Injektivität der Inklusion und Bijektivität der Identität bei der entsprechenden Klassifikation. Bereits in der ersten Migration verschobene Produkt-/Filter-/Termbildsätze werden hier nicht nochmals als neue Funde gezählt.

## K9 — Rechtsinverse vor dem Auswahlprinzip

9.2.1.1 „Rechtsinverse ist injektiv“, Bd. 09 - Auswahlprinzip.tex:47, ohne separate stabile ID:

    F:A→B, G:B→A, F∘G=Id_B ⇒ G:B↣A.

Das Resultat nutzt kein Auswahlaxiom. In der bisherigen Notation ist B08 der direkte frühere Ort, weil dort die Identität eingeführt wird; nach K8 kann eine punktweise Fassung bereits in B06 stehen:

    F:A→B, G:B→A, ∀b∈B F(G(b))=b ⇒ G injektiv.

9.2.1.2 (unbetitelt, dieselbe Datei:91) setzt die äußere Funktion zusätzlich als surjektiv voraus; diese zusätzliche Annahme ist für die Injektivität der inneren Funktion unnötig. Dort heißen die Funktionen in umgekehrter Reihenfolge G und F. Der Schluss folgt außerdem aus K6 und der Injektivität von Id. B09 sollte den Satz zur Auswahl einer bereits existierenden Rechtsinversen nur anwenden. Die Existenz einer Rechtsinversen für jede Surjektion bleibt selbstverständlich beim Auswahlprinzip. ChoiceSetRightInverse (9.3.3.5) ist eine konkrete Auswahlmengenbrücke und wird hier nicht pauschal ausgelagert.

## K10 — Zwei einfache, klare Wechsel nach B12

| Satz / Titel | ID | Quelle | Aussage und Abhängigkeit |
|---|---|---|---|
| 13.2.2.3 Minimum und duales Maximum | DualMinimumEqualsMaximum | Bd. 13 - Schranken, Infima und Suprema.tex:1009 | Unter PartOrd(A,≤), T⊆A und existierendem Minimum: min_(A,≤)(T)=max_(A,≥)(T) |
| 13.2.2.4 Maximum und duales Minimum | DualMaximumEqualsMinimum | dieselbe Datei:1069 | Unter derselben Grundordnung und existierendem Maximum: max_(A,≤)(T)=min_(A,≥)(T) |
| 14.2.3.1 Inklusionsordnung auf einer Mengenfamilie | InclusionOrderOnFamily | Bd. 14 - Paarinfima und Paarsuprema.tex:822 | M⊆P(U) ⇒ PartOrd(M,⊆) |

Die beiden Dualitätssätze benötigen ausschließlich OrderDualRelation, OrderDualPartialOrder, Minimum/Maximum, MinimumUnique/MaximumUnique aus B12 sowie Gleichheitslogik. Sie sollten den Dualitäts-/Extremablock von B12 abrunden. Die Schranken- und Infimumsdualitäten bleiben B13.

Die Inklusionsordnung benötigt nur Reflexivität, Transitivität und Antisymmetrie von ⊆ aus B03 und die Halbordnungsdefinition aus B12. Sogar die Beschränkung M⊆P(U) ist für eine beliebige Mengenfamilie M sachlich nicht nötig; man kann sie zur Intervallanwendung beibehalten oder PartOrd(M,⊆) direkt formulieren. Die späteren Aussagen über Paarinfima/-suprema in Mengenfamilien 14.2.3.2–5 bleiben B14.

## Abdeckung und begründete Grenzen

| Band | Aktive Quelldateien | Registrierte Hauptsätze im aktuellen Inventar | Struktureller Befund |
|---|---:|---:|---|
| B01 | 1 | 0 | Logische Grundregeln und Konventionen; kein früherer Standort. Beschränkte Quantoren liefern bereits Grundlage für K3. |
| B02 | 2 | 272 | Logik einschließlich aktivem Migrationsmodul; passender Zielband für K3. Keine zusätzliche spätere Spezialtheorie in den geprüften Beständen. |
| B03 | 6 | 320 | Allgemeine Mengentheorie samt fünf aktiven Ergänzungen; natürliche Zielstelle für K1/K5. Bereits vorhandene Intervalltheorie berücksichtigen. |
| B04 | 1 | 10 | Mitgliedschaftsrelation und strikte Obermengenrelation führen gerade Totalität vor. Die kurzen mengenbezogenen Typ-/Elementbrücken sind hier sinnvolle Definitionseinführungen, kein gesondertes großes Migrationspaket. |
| B05 | 3 | 126 | Funktionsgrundlagen samt zwei aktiven Ergänzungen; Ziel für K4/K8. Allgemeine Bild-/Urbildsätze liegen bereits passend. |
| B06 | 1 | 36 | Inklusionsvorbereitung K8; eigentliche Injektivitäts-, Schnittbild- und Fallabbildungssätze passend. FamContaining/FamAvoiding/Adjunktion in Abstimmung mit der separaten B46-Prüfung, hier nicht doppelt bewertet. |
| B07 | 5 | 73 | K2/K3/K4/K8. Surjektionsfasern und eindeutige Faktorisierung sind passend; aktive Filter-/Termbildmodule nicht erneut als Neufund ausgeben. |
| B08 | 1 | 94 | K5–K9. Eigentliche bijektive Transporte, Verklebungen, Transpositionen und vorgeschriebene Bijektionswerte bleiben sachlich hier. |
| B09 | 1 | 23 | K9. Auswahlmengen-/Relations-/Surjektionsformen und Retraktionsfasern behandeln Auswahl bzw. ihre konkreten Brücken; kein pauschales Verschieben nach B05. |
| B10 | 2 | 322 | K1/K2 für den allgemeinen Rekursionsunterbau. Arithmetik, Peano-Induktion, natürliche Ordnung und aktives Indexmodul benötigen die natürlichen Zahlen. |
| B11 | 2 | 62 | Äquivalenzklassen, Quotienten und Gleichmächtigkeit samt aktivem Graphmodul liegen passend. Quotientenbild erhält Vereinigung ist eine sinnvolle Anwendung des bereits in B05 vorhandenen allgemeinen Bildsatzes, kein Bedarf an einem nochmals neuen Bildsatz. |
| B12 | 1 | 10 | Passender Zielband K10. Allgemeine Ordnungseinschränkung und Extremeneindeutigkeit sind bereits hier. |
| B13 | 1 | 28 | K10 für Minimum-/Maximumdualität. Schrankenmengen, Infima und Suprema sowie deren Dualität benötigen diesen Band. |
| B14 | 1 | 17 | K10 für Inklusionsordnung. Eigenschaften von Paarinfimum/-supremum bleiben hier. |
| B15 | 1 | 23 | Totalität ist für Paarminimum/-maximum und „minimal ⇒ Minimum“ wesentlich. Die algebraischen Binäroperationsgesetze sind passende Anwendungen von B14; keine zusätzliche neue allgemeine Theorie nötig. |
| B16 | 1 | 11 | Auswahlrelation auf nichtleeren Teilmengen ist Vorbereitung einer konkreten Wohlordnungskonstruktion. ChoiceRelTotal/Elim sind kleine Brücken zu B04, kein eigenständiges großes Migrationspaket. Zermelo, Faserminima und Nat-Wohlordnung brauchen Wahl-/Wohlordnungsbegriffe. |

Die sechs normalisierten bandübergreifenden Formelgleichheiten aus critical-duplicates.json sind keine selbstständigen Beweise für Duplikate: Integer- und Rationalgesetze dürfen trotz ähnlicher Form getrennt bewiesen werden. Die echten allgemeinen Mengen-/Funktionsdopplungen mit B21/B46 liegen in den parallel geprüften Bereichen. Frühere 47 Migrationen werden nicht als neue Vorschläge wiederholt.

## Umsetzungshinweis für eine spätere Entscheidung

Zuerst K3/K4/K5/K10 und die sauber typisierten allgemeinen Kerne von K6/K7 bearbeiten; dort sind Standort und Voraussetzungen besonders klar. K1 ist der größte konzeptionelle Gewinn, braucht aber eine bewusst gewählte kurze allgemeine Erzeugungsdefinition und mehrere überprüfte Instanzen. K2 kann danach oder unabhängig davon anhand der schon bestehenden Filterdefinition bewiesen werden. K8 ist eine didaktische Umordnung eines kleinen Grundlagenteils, keine notwendige Voraussetzung für sämtliche anderen Pakete. Keine Einsparungszahl angegeben: Gegenüberstellung vollständig ausgearbeiteter neuer Beweise wäre dafür erst erforderlich.
