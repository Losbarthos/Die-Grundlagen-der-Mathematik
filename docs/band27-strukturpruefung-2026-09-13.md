# Band 27: Teilmengenregel, Anzahlnotation und Platzierung allgemeiner Sätze

Prüfstand: 13. September 2026, nach Einfügung der Induktionsregeln
27.2.1.17 und 27.2.6.6. Die Nummern beziehen sich auf die aktuellen
Einzelbandregister vor dem Umbau. Diese Notiz dokumentiert die damaligen
Vorschläge. Sie sind inzwischen umgesetzt; die neuen Satznummern und die
ausgeführten Änderungen stehen in der
[Änderungsübersicht](<C:/Latex/Die-Grundlagen-der-Mathematik/docs/band27-umsetzung-2026-09-13.md>).

## 1. Eine lokale Einführungsregel für Teilmengen

Die gewünschte Regel ist sinnvoll und kann in Band 3 unmittelbar bei
Definition 3.5.1.1 eingeführt werden:

\[
 [x\in M]\ \vdots\ x\in N\quad\vdash\quad M\subseteq N.
\]

Das ist die abgeleitete Regel **Teilmengeneinführung**, kurz
\(\subseteq I\). Die lokale Annahme \(x\in M\) wird entlassen.
\(x\) muss beliebig sein und darf in \(M\), \(N\) oder den übrigen
offenen Annahmen nicht frei vorkommen. Parameter bleiben fest.

Der einmalige Nachweis besteht aus Implikationseinführung,
Allquantifizierung und der Definition der Teilmenge:

\[
 [x\in M]\vdots x\in N
 \quad\Longrightarrow\quad
 \forall x\,(x\in M\rightarrow x\in N)
 \quad\Longrightarrow\quad M\subseteq N.
\]

Die Anwendung auf das genannte Beispiel lautet:

\[
 [w\in A^*]\ \vdots\ w\in U\quad\vdash\quad A^*\subseteq U.
\]

In einer Beweistabelle genügt anschließend eine Begründung wie
`Teilmengeneinführung ([i] ⋮ j)`. Das fasst die bisher verschachtelten
Verweise auf Implikationseinführung, Allquantifizierung und Definition
zusammen. Wo diese bereits in einer Tabellenzeile stehen, wird die
Begründung übersichtlicher, aber die Zeilenzahl bleibt gleich. Wo eine
gesonderte Allzeile steht, kann diese entfallen.

Die Regel ersetzt nicht den mathematischen Nachweis des Elementübergangs.
Insbesondere darf in einem Beweis, der die Wortinduktion erst herleitet,
der Übergang von \(w\in A^*\) zu \(w\in U\) nicht schon mit eben dieser
Wortinduktion gerechtfertigt werden. Der Minimalitätsschluss in
27.2.1.16 bleibt dafür der passende Beweisschritt. Dagegen lassen sich
dort die gesonderten Zeilen für \(U\subseteq\mathcal E_A\) bündeln.

Quellen: `Bd. 03 - Mengenlehre.tex:219`,
`tex/b27-word-generated-set.tex` und `tex/b27-word-proof-helpers.tex`.

## 2. Die Anzahlnotation

Wenn mit dem genannten Symbol die Raute \(\#\) gemeint ist, empfehle ich
die Schreibweise \(\#M\) oder bei zusammengesetzten Ausdrücken
\(\#(M\cup\{x\})\). In Band 20, Definition 20.3.8.1, wird daraus:

\[
 \operatorname{Finite}(M)\quad\vdash\quad
 \#M\coloneqq\iota n\,
 \bigl(n\in\mathbb N\land N_{<n}\approx M\bigr).
\]

Der mathematische Begriff ändert sich dadurch nicht. Insbesondere bleibt
die in diesem Band definierte Anzahl zunächst auf endliche Mengen
beschränkt. Die Wortlänge kann weiterhin \(|w|\) heißen; für Wörter gilt
der bewiesene Zusammenhang \(|w|=\#w\).

Die sichtbare Notation ist zentral in
`tex/impl/commands/cardinality.tex:42` definiert. In den aktiven Quellen
kommt `\tCard` derzeit in den Bänden 20, 27 und 37 sowie deren Übersichten
und den eingebundenen B27-Dateien vor. Eine strukturelle Umbenennung
sollte ein semantisches Makro wie `\FiniteCard{M}` verwenden und sämtliche
aktiven Aufrufe einschließlich Formelverweisen umstellen. Die
Ergebniskennungen müssen dadurch nicht ihre Bedeutung ändern.
Anschließend sind Register, abhängige PDFs und Gesamtband neu zu bauen.

In Band 48 existiert außerdem die binäre Schreibweise \(x\mathrel\#\Gamma\)
für die Frische einer Variablen. Das ist syntaktisch von der unären
Anzahl \(\#M\) unterscheidbar. Eine automatische Änderung sollte deshalb
gezielt das Anzahlmakro betreffen und keine vorhandenen Rautezeichen ersetzen.

## 3. Motivation für Definition 27.2.5.1

Die Definition **Anfügungsfunktion des Wortmodells** sollte bleiben und
deutlicher motiviert werden. Der Erzeugungsterm \(J(u,a)\) wurde schon
auf einem größeren Bereich endlicher Mengen eingeführt. Jetzt wird
seine Einschränkung auf Wörter als Funktion mit festem Definitions- und
Zielbereich bereitgestellt:

\[
 \sigma_A:A^*\times A\longrightarrow A^*,\qquad
 \sigma_A(u,a)=J(u,a)=u\cup\{(|u|,a)\}.
\]

Diese Funktion liefert im konkreten Modell die Komponente \(s\) der
späteren abstrakten Wortstruktur \((W,e,s)\). Genau dafür müssen
Funktionstypisierung, Anfang, eindeutige Anfügung und Minimalität
nachgewiesen werden. Die Definition führt somit den vorhandenen
Erzeugungsschritt in die Sprache der folgenden Axiomatik über.

Möglicher Einleitungstext:

> Bisher wurde das Anfügen eines Buchstabens durch den Erzeugungsterm
> \(J(u,a)\) beschrieben. Für die anschließende Axiomatik benötigen wir
> diesen Schritt als Funktion auf der Wortmenge. Wir fassen deshalb die
> Anfügung zu einer Abbildung \(\sigma_A:A^*\times A\to A^*\) zusammen
> und weisen ihre Grundgesetze nach. Sie wird im konkreten Wortmodell
> die Rolle der abstrakten Anfügungsfunktion übernehmen.

Quellen: `tex/b27-word-early-core.tex:3`,
`tex/b27-word-early-core.tex:30`, `tex/b27-word-structure-axioms.tex:30`.

## 4. Maßstab für die Verlagerung

Allgemeine Mengen-, Funktions-, Zahlen- und Baumwerkzeuge sollten im
frühesten Band stehen, der ihre Voraussetzungen bereitstellt. Im Wortband
bleiben ihre Anwendung auf das konkrete Modell, die Verbindung der
Erzeugung mit endlichen Folgen und die anschließende Wort- und
Klammerungstheorie.

Die folgenden Inventare unterscheiden:

- unverändert verlagerbare allgemeine Sätze;
- sinnvolle allgemeinere Fassungen mit einer kurzen Spezialisierung in Band 27;
- Blöcke, deren allgemeine Definitionen gemeinsam mitverlagert werden müssen;
- thematisch passende Sätze, die im Band 27 bleiben sollten.

Ein als H1/H2 bezeichnetes Resultat ist ein registrierter Teilbeweis,
kein zusätzliches Haupttheorem. Diese werden gesondert ausgewiesen.


<!-- INVENTAR -->

Insgesamt ergeben sich **46 Hauptsatzstellen und ein separat nutzbarer
Teilbeweis** als Verlagerungs- oder Zusammenführungskandidaten. Darunter
sind inhaltliche Doppelungen; es sollen also nicht 46 neue, voneinander
unabhängige Grundlagenresultate entstehen. Bei drei Wortfilter-Sätzen
ist zunächst ihre lokale Filterdefinition allgemein zu fassen. Weitere
unten benannte Fälle erfordern die Mitverlagerung einer Definition oder
die Anpassung des Beweises.

### 4.1 Frühe Mengen-, Funktions-, Kardinalitäts- und Folgensätze

| Nummer | Exakter Titel | Quelle | Vollständige Aussage, kompakt | Zielband und Grund / Voraussetzungen |
| --- | --- | --- | --- | --- |
| 27.2.2.1 | Paarzugehörigkeit nach einer Adjunktion | `tex/b27-word-graph-helpers.tex:9` | `(i,b)∈R∪{(n,a)} ⇔ (i,b)∈R ∨ (i=n ∧ b=a)` | **B03**, nach Paaren, Einermengen und Vereinigungen. Alle Voraussetzungen vorhanden; keine Funktion vorausgesetzt. |
| 27.2.2.2 | Alte Fasern bleiben unter der Adjunktion unverändert | `tex/b27-word-graph-helpers.tex:28` | `i≠n ⇒ ∀b ((i,b)∈R∪{(n,a)} ⇔ (i,b)∈R)` | **B03**, zusammen mit 27.2.2.1; alternativ als Vorbereitung auf Funktionserweiterungen in B05. Reine Paarrechnung, `R` beliebig. |
| 27.2.2.3 | Die neue Faser eines erweiterten Funktionsgraphen | `tex/b27-word-graph-helpers.tex:47` | `F:D→B, n∉D ⇒ ∀b ((n,b)∈F∪{(n,a)} ⇔ b=a)` | **B05**, Funktionserweiterungen. Funktionsgraph und Definitionsbereich vorhanden. Der aktuelle Satz benötigt **kein** `a∈B`, weil er nur die neue Faser beschreibt. |
| 27.2.2.4 | Eindeutiger Wert im Zielbereich | `tex/b27-word-graph-helpers.tex:71` | `F:A→B, x∈A ⇒ ∃!y∈B (x,y)∈F` | **B05**, bei Funktionswerten. Funktionstypisierung und Eindeutigkeit vorhanden. |
| 27.2.2.5 | Eindeutige Existenz aus einem festgelegten Wert | `tex/b27-word-graph-helpers.tex:88` | `a∈A, ∀x(P(x)↔x=a) ⇒ ∃!x∈A P(x)` | **B02 in allgemeiner Prädikatsfassung**, **B03 unverändert**. Reine Eindeutigkeitslogik; wörtliche Mengenbindung setzt die Einführung von `∈` voraus. Präzisierung unten. |
| 27.2.2.6 | Kardinalzahl der leeren Menge | `tex/b27-finite-card-induction.tex:9` | `card(∅)=0` | **B20**, unmittelbar nach Definition der endlichen Kardinalzahl. Alle Voraussetzungen vorhanden. |
| 27.2.2.7 | Adjunktion erhöht die Kardinalzahl um eins | `tex/b27-finite-card-induction.tex:29` | `Finite(M), x∉M ⇒ card(M∪{x})=card(M)+1` | **B20**, elementare Kardinalzahlgesetze. Endlichkeitsadjunktion, Anfangsabschnitte und Gleichmächtigkeitstransport frischer Adjunktion aus B11 liegen vor. |
| 27.2.2.8 | Induktion nach der Kardinalzahl einer endlichen Menge | `tex/b27-finite-card-induction.tex:54` | `Q(0), ∀n∈N(Q(n)→Q(n+1)), Finite(M) ⇒ Q(card(M))` | **B20**, nach Natürlichkeit der Kardinalzahl. Zahleninduktion aus B10 und `card(M)∈N` genügen. |
| 27.2.2.9 | Anfügen an eine endliche Folge | `tex/b27-word-graph-adjunction.tex:5` | `n∈N, u:N_{<n}→A, a∈A ⇒ u∪{(n,a)}:N_{<n+1}→A` | **B21**, bei endlichen Folgen. Mengen-/Funktionsgrundlagen aus B03/B05 und Anfangsabschnitte aus B10 vorhanden; Graphenhilfssätze gemeinsam vorordnen. |
| 27.2.2.10 | Ein endlicher Funktionsgraph hat so viele Elemente wie sein Definitionsbereich | `tex/b27-word-characterization.tex:11` | `n∈N, w:N_{<n}→A ⇒ N_{<n}≈w` | **B11 verallgemeinert** zu `F:D→A ⇒ D≈F`; **B21 unverändert** in der aktuellen Folgenfassung. Die Bijektion `i↦(i,F(i))` braucht keine Endlichkeit. B08 hat die Bijektionssprache, aber `≈` wird erst in B11 eingeführt. |
| 27.2.2.11 | Die Graphen endlicher Folgen sind endlich | `tex/b27-word-characterization.tex:71` | `n∈N, w:N_{<n}→A ⇒ Finite(w)` | **B20 verallgemeinert** zu `Finite(D), F:D→A ⇒ Finite(F)`; **B21 unverändert**. Endlichkeitstransport vorhanden; allgemeine Graphkorrespondenz vorher einordnen. |
| 27.2.2.12 | Kardinalzahl eines endlichen Funktionsgraphen | `tex/b27-word-characterization.tex:86` | `n∈N, w:N_{<n}→A ⇒ card(w)=n` | **B20 verallgemeinert** zu `Finite(D), F:D→A ⇒ card(F)=card(D)`; **B21 unverändert**. Graphkorrespondenz und Graphendlichkeit vorordnen; eindeutige endliche Kardinalzahl vorhanden. |
| 27.2.2.14 | Eine endliche Folge aus ihrer Einschränkung zurückgewinnen | `tex/b27-word-characterization.tex:161` | `n∈N, w:N_{<n+1}→A ⇒ w=(w eingeschränkt auf N_{<n})∪{(n,w(n))}` | **B21**, nach dem Anfügungssatz. Einschränkung, Funktionsextensionalität und Anfangsabschnittszerlegung liegen vor. |
| 27.2.2.19(H2) | Eindeutigkeit der Wortlänge | `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex:255` | `(m∈N ∧ w:N_{<m}→A), (n∈N ∧ w:N_{<n}→A) ⇒ m=n` | **B21**, inhaltlich Eindeutigkeit der Länge einer endlichen Folge. Keine Wortzugehörigkeit vorausgesetzt. B05 liefert eindeutigen Definitionsbereich, B10 injektive Anfangsabschnitte. |

Die Voraussetzung `n∈N` von 27.2.2.10 steht derzeit im Delta-Block und ist oben ausdrücklich ergänzt. Das Teilresultat 27.2.2.19(H2) trägt die Kennung `FiniteWordLengthUniquenessPart`; die Registry ordnet es `thm:pp:27.2.2.19:2` zu.

### 4.2 Allgemeine Hilfssätze im axiomatischen Wortteil

In den Quellenlinks bezeichnet die Zahl die Zeile der Satzdeklaration. Die fünf Termbildregeln sind als zusammenhängendes Paket zu verstehen.

| Nummer | Exakter Titel | Aussage | Zielband und Abhängigkeiten | Quelle |
|---|---|---|---|---|
| 27.2.6.4 | Eindeutige Existenz aus einem festen Zeugen | `P(c), ∀x(P(x)→x=c) ⊢ ∃!x P(x)` | **Band 2 – Theoreme der Logik**; reine Gleichheits- und Quantorenlogik. Kein Wort-, Mengen- oder Funktionsbegriff erforderlich. | [word-structure-consequences.tex:42](<C:/Latex/Die-Grundlagen-der-Mathematik/tex/b27-word-structure-consequences.tex:42>) |
| 27.2.6.8 | Elementkriterium einer termgebildeten Menge | `z∈{t(j)∣j∈J} ↔ ∃j∈J: z=t(j)` | **Band 3**, nach 3.18.1.1 „Eindeutige Existenz einer durch Terme beschriebenen Bildmenge“. Benötigt Definition 27.2.6.2 und die Iota-Kennzeichnung. | [word-proof-helpers.tex:19](<C:/Latex/Die-Grundlagen-der-Mathematik/tex/b27-word-proof-helpers.tex:19>) |
| 27.2.6.9 | Termbildung über einer Einermenge | `{t(j)∣j∈{a}}={t(a)}` | **Band 3**, Termbild-Elementkriterium und Einermengen. | [word-proof-helpers.tex:33](<C:/Latex/Die-Grundlagen-der-Mathematik/tex/b27-word-proof-helpers.tex:33>) |
| 27.2.6.10 | Termbildung über einer Vereinigung | `{t(j)∣j∈J∪K}={t(j)∣j∈J}∪{t(j)∣j∈K}` | **Band 3**, Termbild-Elementkriterium, Vereinigung und logische Verteilung von Existenzquantoren über Disjunktion. | [word-proof-helpers.tex:58](<C:/Latex/Die-Grundlagen-der-Mathematik/tex/b27-word-proof-helpers.tex:58>) |
| 27.2.6.11 | Vereinigung einer Einermenge | `⋃{x}=x` | **Band 3**, unmittelbar zur allgemeinen Vereinigung; nur Einermenge, Vereinigung und Extensionalität. | [word-proof-helpers.tex:104](<C:/Latex/Die-Grundlagen-der-Mathematik/tex/b27-word-proof-helpers.tex:104>) |
| 27.2.6.12 | Beschreibung einer Funktionsfaser | `F:A→B, x∈A ⊢ ∀y((x,y)∈F ↔ y=F(x))` | **Band 5 – Funktionen**, nach Funktionsauswertung und Eindeutigkeit eines Funktionswerts. Die Voraussetzung `x∈A` bleibt wesentlich. | [word-proof-helpers.tex:122](<C:/Latex/Die-Grundlagen-der-Mathematik/tex/b27-word-proof-helpers.tex:122>) |
| 27.2.6.13 | Zielmenge einer termgebildeten Menge | `∀j∈J: t(j)∈M ⊢ {t(j)∣j∈J}⊆M` | **Band 3**, Termbild-Elementkriterium und Teilmengenbegriff. | [word-proof-helpers.tex:138](<C:/Latex/Die-Grundlagen-der-Mathematik/tex/b27-word-proof-helpers.tex:138>) |
| 27.2.6.14 | Punktweise gleiche Terme bilden dieselbe Menge | `∀j∈J: t(j)=r(j) ⊢ {t(j)∣j∈J}={r(j)∣j∈J}` | **Band 3**, Termbild-Elementkriterium, voriger Teilmengensatz und beidseitige Inklusion. | [word-proof-helpers.tex:154](<C:/Latex/Die-Grundlagen-der-Mathematik/tex/b27-word-proof-helpers.tex:154>) |

### 4.3 Das allgemeine Filterpaket aus dem Wortrekursionsbeweis

Die lokale Definition 27.2.6.8 „Filter einer einzelnen Faser“ setzt `B=W×X` und

`Φ_(t,c)(K)={p∈B ∣ (π₁(p),π₂(p))∈K ∧ (π₁(p)≠t ∨ π₂(p)=c)}`.

Für eine allgemeine Fassung ersetzt man die wortbezogenen Umgebungsparameter durch beliebige Mengen `U,V`. Weder Wortaxiome noch Rekursion sind für die drei folgenden Sätze nötig. Die Projektionen und ihre Produktregeln liegen aktuell in Band 7: Definitionen 7.3.1.1–2, Satz 7.3.1.10 und insbesondere Satz 7.3.1.11 `ProductComprehensionMembership`. Ein direkt mit Paaren formulierter Relationsfilter wäre auch mit Band 3 möglich, erforderte aber einen entsprechend neuen Beweis.

| Nummer | Exakter Titel | Aussage | Ziel / Empfehlung | Quelle |
|---|---|---|---|---|
| 27.2.6.17 | Ein gefilterter Graph ist eine Teilmenge | `Φ_(t,c)(K)⊆K` | **Band 7 nach Verallgemeinerung**; Aussonderung und Rückgewinnung des Paars aus seinen Projektionen. | [word-axiomatic-recursion.tex:58](<C:/Latex/Die-Grundlagen-der-Mathematik/tex/b27-word-axiomatic-recursion.tex:58>) |
| 27.2.6.18 | Elementkriterium des Faserfilters | `K⊆B ⊢ ((u,x)∈Φ_(t,c)(K) ↔ (u,x)∈K ∧ (u≠t∨x=c))` | **Band 7 nach Verallgemeinerung**; benutzt das allgemeine Produkt-Aussonderungskriterium 7.3.1.11. | [word-axiomatic-recursion.tex:74](<C:/Latex/Die-Grundlagen-der-Mathematik/tex/b27-word-axiomatic-recursion.tex:74>) |
| 27.2.6.23 | Der Filter erzwingt seinen vorgeschriebenen Faserwert | `K⊆B, (t,z)∈Φ_(t,c)(K) ⊢ z=c` | **Band 7 mit dem Filterpaket**; unmittelbare Folgerung aus dem Elementkriterium und `t=t`. | [word-axiomatic-recursion.tex:178](<C:/Latex/Die-Grundlagen-der-Mathematik/tex/b27-word-axiomatic-recursion.tex:178>) |

Die stabilen Schlüssel sind `WordRecursionFilterSubset`, `WordRecursionFilterMembership`, `WordRecursionFilterOwnFiber`; die erforderliche Definition heißt `WordRecursionFiberFilterDef` ([Quelle:21](<C:/Latex/Die-Grundlagen-der-Mathematik/tex/b27-word-axiomatic-recursion.tex:21>)). Diese drei Sätze sind bedingte Kandidaten und nicht in den acht eindeutigen Verlagerungen mitgezählt.

### 4.4 Allgemeine Hilfssätze im Baumteil: Mengen, Termbildung und Zahlen

Dateischlüssel der folgenden Tabellen:

- **M:** Hauptdatei `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`.
- **T:** `tex/b27-tree-early-foundations.tex`.
- **R:** `tex/b27-tree-axiomatic-recursion.tex`.
- **P:** `tex/b27-address-paths.tex`.
- **G:** `tex/b27-general-rooted-trees.tex`.
- **E:** `tex/b27-ranked-parent-proofs.tex`.

| Nummer | Exakter Titel | Aussage in Kurzform | Fundstelle | Zielband und Voraussetzung |
|---|---|---|---|---|
| 27.3.3.1 | Elementkriterium einer zweistelligen Termbildung | `z∈{t(x,y) ∣ x,y∈D}` genau dann, wenn `∃x,y∈D: z=t(x,y)` | T:21 | **Band 7**, nach den Projektionen. Mitnehmen: Definition 27.3.3.1 (`TreeCodeBinaryTermImageDef`, T:11). Der vorliegende Beweis benutzt die Projektionen von `D×D` und `B27TermImageMembership` (derzeit 27.2.6.8). Die einfache Termbilddefinition samt Elementkriterium muss also ebenfalls früher verfügbar werden, sachlich bei der Ersetzung in Band 3. Ein Umzug schon nach Band 3 erforderte eine andere, projektionsfreie Definition; das ist nicht die bestehende Fassung. |
| 27.3.4.12 | Elementkriterium des Baumgraphfilters | Für `G⊆T×X`: `(u,x)∈Ψ_{t,c}(G)` genau dann, wenn `(u,x)∈G ∧ (u≠t ∨ x=c)` | R:283 | **Band 7**, nach Produkt-Aussonderung und Projektionen. Keine Baumstruktur vorausgesetzt. Mitnehmen: Filterdefinition 27.3.4.4 (`BinaryTreeRecursionFilterDef`, R:271); allgemeiner Name wäre sinnvoll. `ProductComprehensionMembership` steht bereits in 7.3.1.11. |
| 27.3.4.13 | Ein Baumgraphfilter ist eine Teilmenge | `Ψ_{t,c}(G)⊆G` | R:310 | **Band 7**, unmittelbar nach voriger Filterdefinition. Nur Aussonderung, Paarrekonstruktion und Teilmengenbegriff. |
| 27.4.1.15 | Ein Paar mit gleichwertiger Zugehörigkeit | Aus `u∈P ↔ v∈P` folgt `{u,v}∩P=∅ ∨ {u,v}∩P={u,v}` | M:4378 | **Band 3**, bei Paarmengen und Schnitten. Benutzt u. a. `PairSetDisjointFromTwoAvoided` = 3.11.3.5; keine Wortabhängigkeit. |
| 27.4.1.16 | Eine leere Menge oder ein verschiedenes Paar | Aus `C=∅ ∨ C={u,v}` und `u≠v` folgt: `C=∅` oder es gibt verschiedene `a,b∈C` mit `C={a,b}` | M:4411 | **Band 3**, Paarmengen/Existenzzeugen. Reine Paarzugehörigkeit und Aussagenlogik. |
| 27.4.1.19 | Ein kleinerer natürlicher Index liegt ebenfalls im Abschnitt | `n,i,j∈N`, `i<j`, `j∈N_{<n}` implizieren `i∈N_{<n}` | P:52 | **Band 10**, Anfangsabschnitte nach strikter Ordnung. Benutzt `PeanoNatSegStrictMembership`, `PeanoLtTransitive`. |
| 27.4.1.21 | Ein Nachfolgerindex liefert den vorherigen Schrittindex | `n,i∈N`, `i+1∈N_{<n+1}` implizieren `i∈N_{<n}` | P:102 | **Band 10**, Anfangsabschnitte. Benutzt die Äquivalenzen `i+1≤n ↔ i+1∈N_{<n+1}` und `i<n ↔ i+1≤n`. |
| 27.4.1.22 | Rückwärtsinduktion auf einem endlichen Anfangsabschnitt | Aus `H(n)` und `∀i<n (H(i+1)→H(i))` folgt `∀i<n+1 H(i)` | P:120 | **Band 10**, nach Anfangsabschnitten und Zahleninduktion. Die beiden benannten Teilbeweise `B27FiniteBackwardInductionBase/Step` mitnehmen; sie sind Teile desselben allgemeinen Satzes, keine zusätzlichen Haupttheoreme. |

### Allgemeine Pfadwerkzeuge: fünf Theoreme

Die Aussagen sind graphenallgemein. Für den kleinsten Eingriff ist das Ziel **Band 26, Kapitel 2 „Endliche einfache Wege“**, wo ihre Voraussetzungen schon stehen: `FiniteSimplePathFamilyMembership` = 26.2.1.1; `FinitePathIndexShiftOne` = 26.2.2.2; `FinitePathTyping` = 26.2.2.3; `FinitePathFreshEndpointExtension` = 26.2.2.11; `FinitePathEndpointStep` = 26.2.2.12. Band 22 wäre thematisch denkbar, verlangt aber zusätzlich die Verlagerung dieses Grundbestands; Band 24/25 bietet für die vorliegenden gerichteten Aussagen keinen passenderen, rückwärtsfreien Ort.

| Nummer | Exakter Titel | Aussage in Kurzform | Fundstelle | Zielband und Voraussetzung |
|---|---|---|---|---|
| 27.4.1.20 | Index- und Knotendaten eines Pfadschritts | Für einen einfachen gerichteten Pfad `p` der Länge `n` und `i<n`: zulässige natürliche Indizes `i,i+1`, Knoten `p(i),p(i+1)∈V` und Kante `(p(i),p(i+1))∈E` | P:70 | **Band 26.2**, nach Pfadtypisierung und Indexverschiebung. Nur bestehende Graph-/Pfad- und Zahlenregeln. |
| 27.4.1.24 | Einführung eines gespeicherten Pfades | Aus den Typdaten eines Pfades `p` von `u` nach `v` mit Länge `n` folgt `(n,p)∈Pfadmenge(V,E,u,v)` | P:230 | **Band 26.2.1**, nach dem Elementkriterium der Pfadmenge. Reine Einführungsregel für das gespeicherte Paar. |
| 27.4.1.25 | Die Bestandteile eines gespeicherten Pfades | Aus `(n,p)∈Pfadmenge(V,E,u,v)` folgen die Typdaten, die Pfadeigenschaft sowie `p(0)=u`, `p(n)=v` | P:269 | **Band 26.2.1**, neben voriger Regel. Elementkriterium und Gleichheit geordneter Paare. |
| 27.4.1.29 | Der Weg aus einem einzigen Knoten | Jeder Graph besitzt zu jedem `r∈V` einen gespeicherten einfachen Weg von `r` nach `r` | P:421 | **Band 26.2**, allgemeine Nullweg-Regel. **Beweis vor Umzug anpassen:** aktuell Zeuge `LetterWord(r)` und Zitate auf Band 27. Ersetzbar durch `p={(0,r)}` mit `SingletonGraphFunction` = 5.3.1.3 und `SingletonGraphValue` = 5.3.1.4 sowie den vorhandenen Abschnittsregeln. Die allgemeine Aussage selbst besteht bereits. |
| 27.4.1.30 | Ein erreichter Knoten führt über eine Kante weiter | Existiert ein gespeicherter einfacher Weg von `r` nach `u` und ist `(u,v)∈E`, so existiert einer von `r` nach `v` | P:466 | **Band 26.2**, nach 26.2.2.12 `FinitePathEndpointStep` und der mitverlagerten Paar-Einführungsregel. Der Satz verlängert nicht ungeprüft einen einfachen Weg: der vorhandene Endpunktschrittsatz behandelt Wiederholungen. |

### Allgemeine endliche Wurzelbäume: neun Theoreme

Der vollständige allgemeine Block **27.4.2.1–27.4.2.9** passt nach **Band 26**, nach den Wurzelwegen und Eltern-/Kindrelationen (Kapitel 4; etwa Anschluss an „Eltern und Kinder“). Er verwendet keine Wort- oder Klammerungsbaumstruktur. Die unmittelbar anschließenden 27.4.2.10–.11 sind Anwendungen auf Positionswörter und bleiben in Band 27.

Mitverlagerbare Definitionen in G:

- **Def. 27.4.2.1, „Endlicher verwurzelter Baum“**, G:22: `EndWBaum(V,E,r) := Finite(V) ∧ RootedTree(V,E,r)`.
- **Def. 27.4.2.2, „Endliches Elternsystem mit Höhenmarken“**, G:73: endliches `V`, `D⊆V×V`, `r∈V`, `h:V→N`, `h(r)=0`, jeder Nichtwurzelknoten hat genau einen eingehenden Elternknoten, entlang jeder Kante wächst `h` streng.
- **Def. 27.4.2.3, „Vergessen der Kantenrichtung“**, G:90: `sym_V(D)={(a,x)∈V×V ∣ (a,x)∈D ∨ (x,a)∈D}`. Die allgemeine Relation könnte alternativ schon in Band 23 eingeführt werden; für den zusammenhängenden Block ist Band 26 ausreichend.

| Nummer | Exakter Titel | Aussage in Kurzform | Fundstelle | Zielband / wichtigste Abhängigkeit |
|---|---|---|---|---|
| 27.4.2.1 | Die Kindermengen eines endlichen Baums sind endlich | Bei endlichem Wurzelbaum und `a∈V` ist `Kinder(a)` endlich | G:37 | **26**, nach Eltern/Kinder; `FiniteSubset` aus 20 und `TreeChildrenMembership` = 26.4.2.8, `TreeParentAccess` = 26.4.2.1. |
| 27.4.2.2 | Graphdaten eines Elternsystems | Ein Elternsystem liefert einen gerichteten Graphen, einen schlichten ungerichteten symmetrisierten Graphen und keine eingehende Kante nach `r` | E:2 | **26**, mit Elternsystem- und Symmetrisierungsdefinition; Graphregeln aus 22–24, Höhenordnung aus 10, Produktaussonderung aus 7. |
| 27.4.2.3 | Höhenzunahme entlang eines gerichteten Elternwegs | Für `i<j` im Pfad gilt `h(p(i))<h(p(j))` | E:35 | **26**, nach vorigem Satz; Pfadtypisierung und Induktion/Transitivität aus 10. |
| 27.4.2.4 | Gerichtete Erreichbarkeit vom Wurzelknoten | Jeder `x∈V` ist durch einen gespeicherten gerichteten einfachen Weg von `r` erreichbar | E:77 | **26**, nach Höhenzunahme; Induktion über eine Höhenschranke, Einermengengraph aus 5 und frische Pfadverlängerung 26.2.2.11. |
| 27.4.2.5 | Jeder einfache Wurzelweg folgt der Elternrichtung | Ein einfacher Pfad des symmetrisierten Graphen mit Start `r` ist bereits ein gerichteter Pfad in `D` | E:130 | **26**, nach Graphdaten; eindeutiger Elternknoten und Pfadinjektivität schließen Umkehrschritte aus. |
| 27.4.2.6 | Eindeutigkeit gerichteter Wurzelwege | Zwei gespeicherte gerichtete Wege von `r` nach demselben `x` stimmen überein | E:178 | **26**, nach vorigen Sätzen; Wohlordnung 10.4.5.24, eindeutige Eltern, Pfadeinschränkung und Funktionsextensionalität. |
| 27.4.2.7 | Eindeutige Wege im symmetrisierten Elternsystem | Jeder Knoten besitzt genau einen gespeicherten Wurzelweg im symmetrisierten Graphen | E:239 | **26**, aus .4, .5, .6 und dem Elementkriterium der Pfadmenge. |
| 27.4.2.8 | Ein Elternsystem trägt einen endlichen Wurzelbaum | `ElterSys(V,D,r,h) ⇒ EndWBaum(V,sym_V(D),r)` | G:102 | **26**, aus .2, .7 und `RootedTreeFromUniqueRootPaths` = 26.4.1.4. |
| 27.4.2.9 | Die gerichteten Kanten sind genau die Baumeltern | Für `a,x∈V`: `(a,x)∈D ↔ a ist Baumelter von x` im symmetrisierten Baum | G:127 | **26**, nach .8; Elternrelation Def. 26.4.2.1, gerichtete Erreichbarkeit, Höhenzunahme, Vorwärtsrichtung und frische Pfadverlängerung. |

## 5. Gemeinsam zu verschiebende Definitionen und Zusammenführungen

| Nummer und Art | Exakter Titel | Inhalt | Zielband und Einschränkung | Quelle |
|---|---|---|---|---|
| Definition 27.2.6.2 | Durch einen Term gebildete Menge | Kennzeichnet `{t(j)∣j∈J}` durch Iota und ihr Elementkriterium. | **Band 3** zusammen mit den fünf Termbildregeln; ihre Existenzgrundlage ist bereits Satz 3.18.1.1 `TermImageSetUniqueExists`. Ein Mengenterm ist hier ausdrücklich keine schon gegebene Funktion. | [word-proof-helpers.tex:8](<C:/Latex/Die-Grundlagen-der-Mathematik/tex/b27-word-proof-helpers.tex:8>) |
| Definition 27.2.9.1 | Funktionsgraph eines binären Operators | `BinOp(A,⋆)` liefert die Funktion `widehat(⋆):A×A→A` mit `widehat(⋆)(x,y)=x⋆y`. | Allgemeines Funktionsgrundlagenmaterial. **Mit dem vorhandenen Beweis nach Band 7**, nach den Projektionen. Der Operatorbegriff liegt bereits in Definition 3.17.2.1, sein Abschlussaxiom in Axiom 3.17.2.1; der Funktionsdefinitionssatz ist 5.2.6.9. Eine Fassung direkt in Band 5 verlangt einen Beweis ohne die erst in Band 7 eingeführten Projektionen oder deren Vorverlagerung. | [Band 27:1858](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 27 - Endliche Wörter und Klammerungsbäume.tex:1858>) |

Die gleich nummerierten **Sätze** 27.2.9.1–4 über Linksfaltung sind davon zu unterscheiden und bleiben in Band 27.

Die drei Definitionen des allgemeinen Wurzelbaumblocks und die
zweistellige Termbildung sind bereits bei den betreffenden Tabellen
genannt. Hinzu kommen die beiden lokalen Faserfilterdefinitionen
27.2.6.8 und 27.3.4.4; hier empfiehlt sich **eine gemeinsame allgemeine
Definition** für Relationen in einem Produkt beliebiger Mengen.

Die Filtertheoreme 27.2.6.17 und 27.3.4.13 sind dieselbe
Teilmengenaussage in unterschiedlicher Notation. Ebenso entsprechen
sich die Elementkriterien 27.2.6.18 und 27.3.4.12. Diese vier Stellen
sollten auf zwei gemeinsam bewiesene allgemeine Regeln verweisen.

Auch die beiden Eindeutigkeitshilfen 27.2.2.5 und 27.2.6.4 sollten
aufeinander abgestimmt werden. Die unmittelbar nach Band 2 passende
Regel lautet:

\[
 P(c),\quad \forall x\,(P(x)\rightarrow x=c)
 \quad\vdash\quad\exists!x\,P(x).
\]

Für die mengenbeschränkte Fassung kann man diese Regel auf das Prädikat
\(x\in A\land P(x)\) anwenden. Alternativ lässt sich einmal die
allgemeine Variante
\(Q(a),\ \forall x(P(x)\leftrightarrow x=a)
\vdash\exists!x(Q(x)\land P(x))\) formulieren.
Die wortwörtliche mengenbeschränkte Aussage gehört erst nach Band 3,
weil Band 2 den Mengenbegriff noch nicht voraussetzen sollte.

## 6. Was in Band 27 bleiben sollte

- Die Konstruktion von \(A^*\), ihre Minimalität und der bewiesene Anschluss
  an endliche Folgen. Die Sätze 27.2.2.13, .15–.19 insgesamt sind gerade
  diese Verbindung; nur der ausgewiesene Teilbeweis .19(H2) ist unabhängig.
- Wortlänge, Leerwort, Buchstabenwörter, Anfügung, W0–W3, Wortinduktion,
  Wortrekursion, Konkatenation, Endzerlegung und Linksfaltung. Die
  allgemeine Operatorgraph-Definition ist davon getrennt zu behandeln.
- Die freien binären Baumstrukturen, ihre konkreten Codes, ihre Induktion
  und Rekursion. Ein Satz über solche algebraischen Baumstrukturen ist
  nicht schon ein allgemeiner graphentheoretischer Satz aus Band 26.
- Die Anwendung der allgemeinen Elternsysteme auf Positionswörter:
  27.4.2.10–.11. Wortadressen, Präfixe, Pfropfung und Positionsrekursion
  bleiben ebenfalls Anwendungen innerhalb von Band 27.
- Kapitel 5: Linksbaum, Blattwörter, Klammerungen und Auswertung.
- Kapitel 6: 27.6.1.1–.3 über eindeutige Isomorphismen freier Wort- und
  Baumstrukturen und das leere Alphabet. Sie benötigen die hier
  entwickelten Strukturaxiome und Rekursionssätze. Am Bandende folgen
  keine weiteren mathematischen Sätze.

Die lokalen Zugriffsregeln für abgeschlossene Rekursionsgraphen
(etwa 27.2.6.15–16 und .19–21) sind Anwendungen ihrer Definitionen.
Man könnte manche mit einer kurzen Begründung unmittelbar verwenden;
eine Verlagerung ihrer wortbezogenen Definitionen in Band 3 wäre
jedoch künstlich.

Ein allgemeiner Satz über die kleinste unter gegebenen Operationen
abgeschlossene Teilmenge könnte zusätzlich die Erzeugungs- und
Rekursionsbeweise vereinheitlichen. Das wäre ein **neuer allgemeiner
Satz**, keine unveränderte Verlagerung der vorhandenen Aussagen
27.2.1.4–17, 27.2.6.22 oder 27.3.4.10–11. Er ist nicht in den
46 Satzstellen mitgezählt.

## 7. Einschätzung und sinnvolle Reihenfolge

1. Die Teilmengeneinführung in Band 3 ergänzen; eindeutige Existenz und
   Termbildregeln in den früheren Grundlagen bündeln. Das vereinfacht
   unmittelbar die Begründungsspalten in vielen Bänden.
2. Die Anzahlnotation zentral auf \(\#M\) umstellen. Dabei bleibt die
   Definition der endlichen Kardinalzahl unverändert und die Wortlänge
   besitzt weiterhin ihre eigene Schreibweise.
3. Die allgemeinen Funktionsgraph-, Kardinalitäts- und Folgensätze an
   geeigneter Stelle in den Bänden 5, 11, 20 und 21 bereitstellen.
   Eine allgemeinere Graphkorrespondenz erspart mehrere Spezialbeweise.
4. Die Termbildung und die beiden Filterfassungen bündeln. Die
   vorliegenden Projektionsbeweise benötigen Band 7; bei einem
   früheren Ziel muss der Beweis entsprechend umgeschrieben werden.
5. Die Pfadregeln und den allgemeinen Elternsystemblock in Band 26
   zusammenführen. Beim Nullweg 27.4.1.29 den Buchstabenwort-Zeugen
   vorher durch den Einermengengraphen \(\{(0,r)\}\) ersetzen.
6. In Band 27 die Anwendungen mit Rückverweisen behalten und die
   Motivation von \(\sigma_A\) ergänzen. Die gewünschte Axiomatik
   bleibt dabei an ihrem jetzigen Platz.

Die Prüfung betrifft die fachliche Platzierung, die expliziten
Voraussetzungen und die Abhängigkeitsrichtung. Sie ist kein erneuter
vollständiger Korrektheitsnachweis aller langen Beweise. Vor einer
tatsächlichen Verlagerung sind bestehende äquivalente Resultate in
den Zielbänden zusammenzuführen und danach sämtliche Register und
Querverweise neu aufzubauen.
