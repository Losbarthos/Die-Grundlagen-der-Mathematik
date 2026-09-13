# Konzept: Induktionsregeln und kürzere Beweise in Band 27

Der passende Zusatz unmittelbar nach Theorem 27.2.1.16 ist eine
Induktionsregel für Wörter mit lokalen Annahmen. Für eine natürliche Zahl
`n` gibt es die entsprechende Zahlenregel bereits in Band 10. Die beiden
Anwendungen sollten sprachlich und in den Begründungen unterschieden werden.

Dieses Konzept dokumentiert den Stand vor der Umsetzung. Die angegebenen
Theoremnummern beziehen sich auf diesen Stand. Der anschließend beauftragte
Umbau ist im [Umsetzungsbericht](band27-induktionsregeln-umsetzung-2026-09-13.md)
festgehalten. Zeilenzahlen bezeichnen Beweiszeilen der Tabellen und keine
PDF-Zeilen oder zugesicherten Seitenersparnisse.

## 1. Zusatz direkt nach 27.2.1.16

Vorgeschlagener Titel: **Induktionsregel für erzeugte Wörter**.
Vorgeschlagene interne Kennung: `GeneratedWordInductionRule`.

\[
 P(\varnothing),\qquad
 [u\in A^*,\ a\in A,\ P(u)]\ \vdots\ P(J(u,a)),\qquad
 v\in A^*
 \quad\vdash\quad P(v).
\]

Dabei ist `J(u,a) = u ∪ {(card(u),a)}` die bereits definierte Anfügung.
Die Regel hat drei Eingaben: einen Beweis des Anfangs, einen lokalen
Schrittbeweis und die Zugehörigkeit des betrachteten Wortes zur Wortmenge.
Sie ermöglicht die Begründung „Wortinduktion (IA, IS, Zugehörigkeit)“.

Der Nachweis verwendet ausschließlich 27.2.1.16: Die drei lokalen Annahmen
werden im Schritt entladen; anschließend wird über `u` und `a` quantifiziert.
Damit liegt genau die zweite Voraussetzung von 27.2.1.16 vor. Dessen Anwendung
liefert `P(v)`. Es handelt sich um eine abgeleitete Regel, nicht um ein
zusätzliches Axiom. Wortlänge, Endzerlegung und spätere Wortaxiome werden
dabei nicht vorausgesetzt.

Die Schrittvariablen `u` und `a` müssen beliebig sein und dürfen nicht in den
weiter geltenden Annahmen frei vorkommen. Parameter wie das Alphabet oder
zwei für einen Assoziativitätsbeweis festgehaltene Wörter dürfen erhalten
bleiben. Die Induktionsvoraussetzung darf im Schritt auch unbenutzt bleiben.

Als Vorbild eignet sich insbesondere die Regelgestalt in Band 10,
Theorem 10.2.5.13. Dort werden Zahlen, hier Wörter durchlaufen; deshalb ist
`P(w)` für diese Anwendung die klarere Schreibweise als `P(n)`.

## 2. Anschluss an die spätere Axiomatik

Nach 27.2.6.5 „Induktion in einer Wortstruktur“ kann dieselbe Regelgestalt
für eine beliebige Wortstruktur `(W,e,s)` abgeleitet werden:

\[
 \mathsf{WortStr}_A(W,e,s),\quad P(e),\quad
 [u\in W,\ a\in A,\ P(u)]\ \vdots\ P(s(u,a)),\quad
 v\in W\quad\vdash\quad P(v).
\]

Aus der punktweisen Form erhält man bei Bedarf `∀v∈W P(v)` durch
Allquantifizierung. Für Beweise über beliebige Wortstrukturen ist diese aus
W3 abgeleitete Fassung zu verwenden. Die frühe Regel über das konkrete
`A*` allein rechtfertigt solche allgemeinen Aussagen nicht.

## 3. Konkrete Anwendungen

| Aktuelles Theorem | Konzept und erwartbarer Gewinn |
| --- | --- |
| **27.2.2.13 – Die Erzeugungsregeln liefern lückenlose Funktionsgraphen** | Direkter Anwender der frühen Wortregel. Die letzte Zeile des Induktionsschritts mit dem vollständig quantifizierten Abschluss entfällt: zunächst **eine Beweiszeile**. Der eigentliche Graphbeweis bleibt. |
| **27.2.6.6 – Eindeutige Endzerlegung in einer Wortstruktur** | Die spätere lokale Regel liefert die punktweise Zerlegung unmittelbar aus Anfang und Schritt. Die künstliche Implikation mit unbenutzter Induktionsvoraussetzung sowie universeller Abschluss und anschließende Spezialisierung lassen sich vereinfachen. Größenordnung: **zwei bis drei Zeilen**; der Eindeutigkeitsbeweis bleibt erforderlich. |
| **27.2.6.25 – Der kleinste Rekursionsgraph ist eine Funktion** | Das Prädikat ist `P(u) := ∃!x∈X (u,x)∈G`. Anfang und Schritt sind schon in 27.2.6.23 und 27.2.6.24 bewiesen. Die Regel kann diese beiden Resultate direkt als Induktionsdaten benutzen. Der Nachweis, dass der Graph eine Teilmenge von `W×X` ist, bleibt nötig. |
| **27.2.7.17 – Assoziativität der Wortkonkatenation** | Für feste `u,v` wird bereits über `P(t) := (uv)t = u(vt)` induziert. Mit der lokalen Regel kann unmittelbar auf das betrachtete `w` geschlossen werden. Der universelle Abschluss des Schritts und die anschließende Spezialisierung entfallen: etwa **18 auf 16 Zeilen**. Die Konkatenationsgleichungen im Schritt bleiben unverändert erforderlich. |

Die reine Regelergänzung verbessert vor allem Einheitlichkeit und Lesbarkeit.
Die vorhandenen Tabellen fassen Quantorenoperationen bereits stark zusammen;
deshalb spart sie allein meistens nur wenige Zeilen.

Eine zusätzliche, davon unabhängige Vereinfachung betrifft 27.2.2.13:
Für Wortargumente kann man als Induktionseigenschaft nur die Graphentypisierung
`u : N_<card(u) → A` betrachten. Die Endlichkeit folgt schon aus `u∈A*`
durch 27.2.1.11 und muss nicht nochmals als Konjunkt mitgeführt werden.
Die benötigten Endlichkeits- und Typisierungsvoraussetzungen der Kardinalzahl
müssen bei jeder Anwendung weiter vorliegen. Mit dieser Prädikatswahl und
der kurzen Regel ist ein Entwurf mit ungefähr **18 statt 25 Zeilen** möglich.
Vor einer Übernahme ist die Bereichsbindung des Prädikats ausdrücklich zu
halten; die erst später eingeführte Wortlängennotation wird hier nicht benutzt.

## 4. Wenn P(n) wirklich eine Aussage über natürliche Zahlen bedeutet

Die benötigten Ergebnisse stehen bereits in Band 10:

- **10.4.4.16:** vollständige Induktion mit `+1`, in allquantifizierter Form.
- **10.4.4.17:** die entsprechende Regel mit lokalem Induktionsschritt und
  punktweisem Schluss `P(n)`.

Ein Rückverweis auf diese beiden Sätze genügt. Für die folgenden Einsparungen
wird kein neuer Zahleninduktionssatz in Band 27 benötigt.

**27.2.2.15 – Jede endliche Folge wird durch die Wortregeln erzeugt.**
Hier ist bereits das richtige Zahlenprädikat vorhanden:

\[
 Q(n)\;:\!\iff\;
 \forall u\,(u:\mathbb N_{<n}\to A\ \Rightarrow\ u\in A^*).
\]

Anfang und Schritt bleiben erhalten. Anschließend ist der Schluss:

1. `n∈N` – Voraussetzung.
2. `w : N_<n → A` – Voraussetzung.
3. `Q(n)` – 10.4.4.17 mit IA, IS und Zeile 1.
4. `w∈A*` – Einsetzen von `w` in Zeile 3 und Anwenden auf Zeile 2.

Das ersetzt den bisherigen Schluss über `Finite(w)`, `Q(card(w))` und
`card(w)=n`: **vier statt sieben Schlusszeilen**. Zusätzlich entfällt die
letzte universelle Abschlusszeile des Induktionsschritts, insgesamt also
**vier Beweiszeilen**. Die Bindung des beliebigen Graphen `u` beim Beweis
von `Q(k+1)` bleibt notwendig. Eine Wortinduktion über `w` wäre hier
zirkulär: Die Mitgliedschaft `w∈A*` soll erst bewiesen werden.

**27.2.2.8 – Induktion nach der Kardinalzahl einer endlichen Menge.**
Falls der Satz als bequeme Schnittstelle erhalten bleiben soll, reichen
fünf Tabellenzeilen: die drei Voraussetzungen `Q(0)`, der Zahlenschritt und
`Finite(M)`; dann `card(M)∈N` durch 20.3.8.9; schließlich `Q(card(M))` durch
10.4.4.16 und Einsetzen. Bei separat ausgeschriebener universeller Aussage
sind es sechs Zeilen. Der aktuelle Beweis hat **20 Zeilen**.

Nach Umstellung von 27.2.2.15 wird 27.2.2.8 im aktiven Manuskript nicht mehr
benötigt. Auch **27.2.2.7**, die Adjunktionsformel der Kardinalzahl, hat
gegenwärtig nur diesen einen Anwender. Beide Sätze können alternativ aus
dem notwendigen frühen Aufbau entfallen; **27.2.2.6**, die Kardinalzahl der
leeren Menge, wird weiterhin gebraucht. Kürzen und Entfernen dieser
Hilfssätze sind alternative Entwurfsentscheidungen, keine additiven Gewinne.

Eine aus der Worterzeugung begründete Längeninduktion wäre an der frühen
Stelle verfrüht: Die Aussage `card(J(u,a))=card(u)+1` wird dort noch nicht
als Worteigenschaft zur Verfügung gestellt. Insbesondere dürfen bei einem
leeren Alphabet keine Wörter jeder natürlichen Länge vorausgesetzt werden.
Die vorhandene Zahleninduktion hat dieses Problem nicht.

## 5. Größere Vereinfachung durch ein anderes Induktionsprädikat

**27.2.6.27 – Eindeutigkeit der Wortrekursion** hat derzeit 29 Beweiszeilen.
Der Beweis zeigt erneut die Abgeschlossenheit eines Lösungsgraphen und
verwendet die Minimalität des konstruierten Graphen.

Ein kürzerer Entwurf verwendet stattdessen `P(u) := F(u)=G(u)`:
Am Anfang liefern beide Rekursionsgleichungen denselben Wert. Im Schritt
folgt aus `F(u)=G(u)` die Gleichheit

\[
 F(s(u,a))=r(F(u),a)=r(G(u),a)=G(s(u,a)).
\]

Die abstrakte Wortinduktion und Funktionsextensionalität liefern `F=G`.
Die Rekursionsgleichungen von `G` stehen bereits in 27.2.6.26 zur Verfügung;
der Beweis braucht deshalb keinen späteren Rekursionseindeutigkeitssatz.
Ein Entwurf mit **etwa 16–18 Zeilen** ist plausibel. Der größere Gewinn
kommt hier vom Wechsel des Beweiswegs; die lokale Regel vereinfacht
zusätzlich den Induktionsabschluss.

Ein weiterer, unabhängiger Kürzungskandidat ist **27.5.2.5 – Jedes nichtleere
Wort wird von einem Baum geklammert**. Der Linksbaum aus **27.5.1.23** liefert
bereits einen konkreten Zeugen. Statt des erneuten Induktionsbeweises mit
21 Zeilen sind Zugehörigkeitsannahme, Linksbaumsatz und Existenz-Einführung
ausreichend. Das ist ein Gewinn durch einen vorhandenen Zeugen und keine
Wirkung einer neuen Induktionsregel.

## 6. Empfohlene Reihenfolge

Zuerst die kurze Wortregel nach 27.2.1.16 ergänzen und an 27.2.2.13 verwenden.
Danach die Zahleninduktion in 27.2.2.15 direkt auf Band 10 stützen und über
die beiden dadurch entbehrlichen Kardinalitätshilfen entscheiden. Im
axiomatischen Teil die entsprechende lokale Regel aus 27.2.6.5 ableiten
und insbesondere Assoziativität und Rekursionseindeutigkeit vereinfachen.

Die bereits kurze Schnittminimalität 27.2.5.9 benötigt keinen neuen
Induktionsbeweis. Im Baumteil bleiben die binäre Strukturinduktion und die
bereits vorhandene Zahleninduktion für Stufen, Indizes und Ränge passend.

Beim späteren Umbau sollten außerdem zwei noch vorhandene Erläuterungen
angepasst werden: `b27-word-finite-induction.tex` beschreibt die frühe
Minimalität noch als Beweis durch Endlichkeitsinduktion, und
`b27-bracketing-existence.tex` ordnet die Wortinduktion noch der
Endlichkeitstheorie zu. Beide Texte müssen den tatsächlich verwendeten
Erzeugungs- beziehungsweise Strukturbeweis nennen.

Geprüfte Hauptquellen: `b27-word-generated-set.tex`,
`b27-word-characterization.tex`, `b27-finite-card-induction.tex`,
`b27-word-structure-consequences.tex`, `b27-word-axiomatic-recursion.tex`,
`b27-associativity-from-axioms.tex` und die aktuellen Ergebnisregister.
