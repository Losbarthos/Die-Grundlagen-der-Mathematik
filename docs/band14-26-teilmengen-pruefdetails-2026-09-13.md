# Zweite Teilmengenprüfung: Bände 14–26

Stand: aktive Quellen am 13.09.2026, aktuelle Nummern aus `registry/_B14.registry.tsv` bis `_B26.registry.tsv`. Nur gelesen; keine Manuskriptänderungen und keine Builds. Diese Notiz ist die einzige neu geschriebene Datei.

## Ergebnis und Prüfumfang

**Keine weitere echte Beweiskürzung durch `SubsetIntroductionRule` gefunden.** Die bereits umgestellten 37 Anwendungen decken die ausdrücklich geführten lokalen Elementbeweise mit anschließendem Teilmengenschluss ab. Die übrigen Teilmengenschlüsse verwenden überwiegend bereits einen passenden Mengen-, Bild-, Ordnungs- oder Induktionssatz. Ein erneuter Elementbeweis wäre dort länger.

Das aktive Gesamtinventar `tmp/b27-second-audit/coverage.json` erfasst für diesen Bereich 18 Quelldateien mit 9.559 Beweiszeilen und 693 Beweiszeilen mit Teilmengen- oder Obermengenformeln (einschließlich echter Inklusionen). Beide Formelseiten von `proofstepwide` werden berücksichtigt; verschachtelte `\iffalse`-Blöcke sind maskiert. Insbesondere enthält der korrigierte Wert für Band 20 nur die 1.913 aktiven Beweiszeilen; 367 historische, auskommentierte Zeilen zählen nicht mit. Zusätzlich wurden Quantor-/Implikationsabschlüsse mit Elementformeln, Äquivalenzen und die Verwendung von Elementlemmata für Teilmengenaussagen geprüft. Die Liste der Quellen wurde rekursiv aus den aktiven `\input`-Anweisungen gewonnen; Implementierungs- und Übersichtsdateien wurden nicht als mathematische Quellen gezählt.

Die Zahlen sind ein Inventar von Formeln, keine Behauptung, dass alle 693 Formeln eigenständige Teilmengenabschlüsse seien. Darunter befinden sich etwa Aussagen über die Ordnung `\subseteq`, Konjunktionen, Annahmen und Existenzformeln.

| Band | Aktive Dateien | Aktive Beweiszeilen | Zeilen mit Inklusionsformel | Bestehende Regelanwendungen | Weitere echte Kürzungen durch die Regel |
|---|---:|---:|---:|---:|---:|
| 14 | 1 | 241 | 67 | 0 | 0 |
| 15 | 1 | 314 | 8 | 0 | 0 |
| 16 | 1 | 130 | 5 | 0 | 0 |
| 17 | 1 | 1.480 | 2 | 0 | 0 |
| 18 | 1 | 929 | 12 | 0 | 0 |
| 19 | 1 | 1.848 | 144 | 21 | 0 |
| 20 | 2 | 1.913 | 315 | 14 | 0 |
| 21 | 2 | 1.104 | 56 | 0 | 0 |
| 22 | 1 | 205 | 10 | 0 | 0 |
| 23 | 1 | 69 | 4 | 0 | 0 |
| 24 | 1 | 31 | 2 | 0 | 0 |
| 25 | 1 | 9 | 0 | 0 | 0 |
| 26 | 4 | 1.286 | 68 | 2 | 0 |
| **Summe** | **18** | **9.559** | **693** | **37** | **0** |

Zusätzlich zu den jeweiligen Hauptdateien wurden diese aktiven Module geprüft:

- `tex/b20-migrated-graph-finite.tex`
- `tex/b21-migrated-graph-sequences.tex`
- `tex/b26-migrated-tree-path-rules.tex`
- `tex/b26-migrated-tree-parent-systems.tex`
- `tex/b26-migrated-tree-parent-proofs.tex`

## Bandweise Begründung der Negativbefunde

| Band | Konkrete aktuelle Fundstelle | Warum keine weitere Regelkürzung |
|---|---|---|
| 14 | 14.2.3.2 „Paarmengeninfimum in einer Mengenfamilie“, Hauptdatei:914–917; 14.2.3.3 „Paarmengensupremum in einer Mengenfamilie“, :982–985 | `Z⊆X∩Y` bzw. `X∪Y⊆Z` folgt bereits in einer Zeile aus den beiden Teilmengenprämissen. Die anschließende Generalisierung läuft über eine ganze untere/obere Schranke `Z`; sie ist kein fehlender Elementabschluss. `Z` kommt zudem in der zu generalisierenden Mengenrelation selbst vor. |
| 15 | 15.2.3.11 „Existenz des Paarmengeninfimums in totalen Ordnungen“, Hauptdatei:567; entsprechende Paarmengenbeweise :368,468,630,694,757 | Alle sechs abgeleiteten Inklusionen sind `{x,y}⊆A` aus `x,y∈A` mit dem vorhandenen Paarmengensatz. Die neue Regel würde eine zusätzliche beliebige Elementvariable, Paarmengenelimination und Fallunterscheidung verlangen. |
| 16 | 16.2.1.1 „Auswahlrelation ist total“, Hauptdatei:128; 16.2.1.7 „Wohlgeordnete Fasern liefern eine Auswahlmenge“, :351–355 | Die Auswahlrelation liegt aufgrund ihrer Aussonderungsdefinition im Produkt. Das Faserbild liegt aufgrund des Bildsatzes in `P(B)`; `X⊆B` ist anschließend die Elimination von `X∈P(B)`. Kein lokaler Elementbeweis wird abgeschlossen. |
| 17 | 17.2.3.4 „Die natürliche Kopie ist eine Teilmenge der ganzen Zahlen“, Hauptdatei:642–646 | Bild einer Funktion liegt im Zielbereich; anschließend wird nur die Definition der eingebetteten Kopie eingesetzt. Die übrigen geprüften Allquantoren betreffen Quotientenrepräsentanten und wohldefinierte Operationen, nicht die Einführung einer Teilmenge. |
| 18 | 18.2.3.3 „Geschachtelte natürliche und ganzzahlige Kopien in den rationalen Zahlen“, Hauptdatei:512–534; 18.4.1.2 „Quotientenabstieg der rationalen Ordnung“, :2574 | Bildmonotonie, Bildtypisierung und Transitivität sind jeweils bereits einzelne passende Schlüsse. Der Ordnungsgraph ist durch seine Definition eine Teilmenge von `Q×Q`. Die Quantorabschlüsse der Quotientenoperationen brauchen weiterhin ihre Typisierungs-/Verträglichkeitsaussagen. |
| 19 | Bestehende 21 Anwendungen insbesondere bei Hauptschnitten, Schnittvereinigung, Addition, Negation, Inversen und rationaler Einbettung; z.B. :619,1034,1051,1246,2084,2096,3976,4026,7569,7583 | Die ausdrücklich aufgebauten lokalen Elementargumente sind bereits umgestellt. Die übrigen echten Inklusionen folgen direkt aus Schnittordnung, Bildsätzen, Schnittdefinitionen oder Transitivität. Drei abgekürzte Schnittargumente benötigen mehr Explizitheit, aber keine kürzere Darstellung; siehe unten. |
| 20 | 20.3.7.25 „Monotonie der wachsenden Rekursion“, Hauptdatei:3733–3742; 20.3.7.49 „Punktweise Übersetzung eines komplementdualen Maximums“, :4646–4647; 20.6.1.7 „Abgeschlossenheit des Cantor--Bernstein-Teils“, :6892–6895 | Bei der Rekursion wird über den Index generalisiert; beim Maximum wird `Y⊆X→Y=X` bewiesen. Das sind keine Elementannahmen der benötigten Form. In der Cantor--Bernstein-Abgeschlossenheit wird die definierende Bedingung für alle abgeschlossenen Kandidaten `X` bewiesen; diese Quantoren müssen erhalten bleiben. Die eigentlichen äußeren Teilmengenabschlüsse sind bereits umgestellt. Zwei nur implizite Schlüsse in 20.3.6.15 sind unten gesondert vermerkt. |
| 21 | 21.2.3.2 „Eigenschaften der eingeschränkten Familie“, Hauptdatei:384–389; 21.4.3.1 „Additive Verschachtelung einer wachsenden Mengenfolge“, :1169–1197; 21.4.3.2 „Verschachtelung einer wachsenden Mengenfolge“, :1234–1240 | Bildmonotonie und Gleichheitseinsetzung bzw. Induktion und Transitivität sind bereits kürzer. Im Schluss der Verschachtelung muss der Existenzzeuge `k` für `m+k=n` entlassen werden; eine Teilmengenregel ersetzt dieses `EE` nicht. Die neue Graphadjunktion verwendet vorhandene Produkt-, Einzelmengen- und Vereinigungslemmata. |
| 22 | 22.2.3.1 „Der Umkehrgraph ist ein Graph“, Hauptdatei:292–294; 22.2.3.3 „Der induzierte Teilgraph ist ein Graph“, :391–393 | Aussonderung liegt im Grundbereich bzw. Durchschnitt liegt im zweiten Faktor. Jeweils ein Mengensatz plus Definitionseinsetzung. Ein lokaler Paarbeweis wäre länger und müsste zunächst mit einem beliebigen Graphenelement beginnen. |
| 23 | 23.2.1.2 „Einführungskriterium für ungerichtete Graphen“, Hauptdatei:117–120 | Die zwei Quantorabschlüsse beweisen Symmetrie von Kanten bei festem bzw. beliebigem `x,y∈V`. Eine Annahme `(x,y)∈E` allein ist keine beliebige Elementvariable für die Teilmengenregel. Der Beweis verlangt außerdem Symmetrie, nicht eine neue Graphinklusion. |
| 24 | Hauptdatei vollständig | Nur zwei Teilmengenformeln in Annahmen; kein abgeleiteter Teilmengenschluss. |
| 25 | Hauptdatei vollständig | Keine Teilmengenformel in einer Beweiszeile. |
| 26 | 26.2.2.17 „Umkehrschritt“, Hauptdatei:1481–1489; lokale Bildinklusion :906; `tex/b26-migrated-tree-parent-systems.tex`:48 | Die beiden tatsächlichen lokalen Elementabschlüsse nutzen die Regel bereits. Beim Umkehrschritt sind die weiteren Inklusionen Transitivität, Einzelmengen-/Vereinigungsregel und Einsetzung der Bildgleichheit. Auch die aktiven neuen Pfad-/Elternsystemmodule enthalten keinen weiteren unentladenen Elementbeweis mit Teilmengenziel. |

## Zusätzliche Explizitheitsfälle, ausdrücklich keine Zeilenkürzungen

### 1. Band 20: Elementlemma wird unmittelbar als Teilmengensatz benutzt

**20.3.6.15 „Zerlegung der Potenzmenge einer Nachfolgermenge“**, `Bd. 20 - Endliche Mengen.tex`:2445 und :2447.

Die beiden zitierten Hilfssätze **20.3.6.15(H1)** und **20.3.6.15(H2)** haben laut aktueller Registry die Form `n∈N, Y∈L ⊢ Y∈R` bzw. `n∈N, Y∈R ⊢ Y∈L`. Im Schluss werden sie nur mit `n∈N` unmittelbar für `L⊆R` bzw. `R⊆L` verwendet. Dabei sind

`L=P(NatSeg(n+1))`, `R=P(NatSeg(n)) ∪ PowAdj_n[P(NatSeg(n))]`.

Eine ausdrücklich gültige Schlussfassung wäre:

| Zeile | Aussage | Grund |
|---:|---|---|
| 1 | `n∈N` | Annahme |
| 2 | `[Y∈L]` | lokale Annahme, `Y` frisch |
| 3 | `Y∈R` | H1 aus 1,2 |
| 4 | `L⊆R` | `SubsetIntroductionRule`, `[2]⋮3` |
| 5 | `[Y∈R]` | neue lokale Annahme |
| 6 | `Y∈L` | H2 aus 1,5 |
| 7 | `R⊆L` | `SubsetIntroductionRule`, `[5]⋮6` |
| 8 | `L=R` | Antisymmetrie aus 4,7 |

Das wären **8 statt 4 Schlusszeilen**, also keine Kürzung. Alternativ könnten die beiden Hilfsteilbeweise selbst um den Regelabschluss erweitert und ihre registrierten Aussagen in echte Inklusionen umformuliert werden; auch das ist eine strukturelle Korrektur, keine wegfallende Quantorzeile im aktuellen Text. Die bereits in H1/H2 enthaltenen lokalen Zeugen- und Fallannahmen müssen vor dem jeweiligen Regelabschluss entlassen sein.

### 2. Band 19: Drei nur zusammengefasst begründete Schnittinklusionen

**19.6.1 „Archimedische Eigenschaft der reellen Zahlen“**, `Bd. 19 - Reelle Zahlen.tex`:5247, derzeit Beweiszeile 7:

Aus `x∈R`, `q∈Q\x` und `q<r`, wobei `r=RatEmbed(IntEmbed(n))`, wird `x⊆RealHat(r)` lediglich mit `DedekindCutCharacterization` begründet. Eine explizite lokale Ableitung lautet:

`[a∈x]` → `a<q` nach **19.4.2.1(H1)** `RealCutMemberBelowExterior` → `a<r` durch strikte Transitivität → `a∈RealHat(r)` nach Hauptschnittdefinition → `x⊆RealHat(r)` durch Teilmengeneinführung.

Die rationale Typisierung von `q,r,a` muss aus den vorhandenen Voraussetzungen bzw. Einbettungs-/Schnittsätzen bereitstehen. `a` ist frisch und wird entlassen. Diese Darstellung braucht mehr Zeilen als der bisherige einzelne verkürzte Verweis.

**19.6.3 „Dichtheit der rationalen Zahlen in den reellen Zahlen“**, dieselbe Datei:5404, derzeit Beweiszeile 10:

Aus `b∈y\x` und `q∈y`, `b<q` wird `x⊆RealHat(q)` ebenso nur mit `DedekindCutCharacterization` begründet. Explizit:

`[a∈x]` → `a<b` nach `RealCutMemberBelowExterior` (mit `b∈Q` aus `b∈y`) → `a<q` → `a∈RealHat(q)` → Teilmengeneinführung.

**19.6.3**, dieselbe Datei:5413, derzeit Beweiszeile 14:

`[a∈RealHat(q)]` → `a∈Q ∧ a<q` nach Hauptschnittdefinition → `a∈y` aus `q∈y` und Abwärtsabschluss des Schnittes → `RealHat(q)⊆y` durch Teilmengeneinführung.

Auch hier ist `a` jeweils unabhängig von den Mengenparametern und übrigen offenen Annahmen. Die Regel würde den bisher zusammengefassten Übergang sichtbar machen. **Diese drei Fälle dürfen nicht als eingesparte Zeilen gezählt werden.**

## Ein umgekehrter Kandidat: vorhandener Satz kürzer als die neue Regel

**20.6.1.4 „Die Cantor--Bernstein-Teilmenge liegt im Ausgangsbereich“**, `Bd. 20 - Endliche Mengen.tex`:6748–6755, ID `CantorBernsteinPartSubset`.

Der aktuelle Beweis hat fünf Zeilen: zwei Funktionsannahmen, `[x∈CBPart(F,G)]`, daraus `x∈A`, dann Teilmengeneinführung. Eine vierzeilige Fassung ist bereits mit früheren Sätzen möglich:

1. `F:A↪B` (Annahme).
2. `G:B↪A` (Annahme).
3. `CBPart(F,G)={z∈A | P(z)}` nach `CantorBernsteinPartDef` aus 1,2.
4. `CBPart(F,G)⊆A` nach dem vorhandenen Satz `C={z∈A | P(z)} ⊢ C⊆A` aus 3.

Das spart **eine Zeile durch einen direkten Aussonderungssatz**, nicht durch eine zusätzliche Anwendung der neuen Regel. Keine Änderung vorgenommen. Die übrigen geprüften direkten Mengen- und Bildsätze sollten aus demselben Grund nicht künstlich in Elementbeweise zurückübersetzt werden.

## Grenzen der Regel in dieser Prüfung

- Eine bereits bewiesene Inklusion wird durch Transitivität oder einen Mengen-/Bildsatz oft in genau einer Zeile weiterverwendet; die Teilmengeneinführung liefert dort keine kürzere Ableitung.
- Eine Quantifizierung über einen Index, eine Schranke, eine Kandidatenmenge oder einen Existenzzeugen darf nicht mit einer beliebigen Elementvariablen verwechselt werden.
- Aus einer Annahme `(u,v)∈G` darf ohne beliebiges `p∈G` und passende Paarzerlegung keine allgemeine Inklusion `G⊆H` durch die neue Regel gewonnen werden.
- Eine bloße Äquivalenzelimination `X∈P(A) ⇒ X⊆A` ist bereits ein direkter Satzaufruf. Sie braucht keinen lokalen Elementbeweis.
- Offene Fallannahmen und Existenzzeugen bleiben unabhängig vom Teilmengenabschluss korrekt zu entlassen. Die Regel erspart nur die zum Elementabschluss gehörige Implikations-/Allquantoreinführung und das anschließende Entfalten der Teilmengendefinition.
