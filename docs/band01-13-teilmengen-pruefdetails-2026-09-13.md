# Zweite Prüfung der Teilmengenbeweise: B01–B13

Stand: 2026-09-13. Nur aktuelle Quellen gelesen; keine Manuskriptänderungen und keine Builds. Die Registerzahlen beziehen sich auf die aktuelle Haupt-/Einzelbandausgabe.

## Umfang und Ergebnis

Aktive Hauptdateien und ihre tatsächlich eingebundenen Module wurden rekursiv erfasst; Kommentare und `\iffalse`-Blöcke wurden ausgeschlossen. Nach Einbeziehung beider Formelseiten von `proofstepwide` stimmen die Zahlen mit dem aktualisierten `coverage.json` überein: **14.705 Beweiszeilen, 947 Zeilen mit Teil-/Obermengennotation und 118 vorhandene Anwendungen der neuen Regel**. Die 118 Anwendungen verteilen sich auf zehn der ersten dreizehn Bände.

Zusätzlich zu verbliebenen Definitionsverweisen wurden sämtliche Teilmengenfolgerungen, geteilte `proofstepwide`-Formeln, Allquantor-/Implikationsabschlüsse und die lokalen Anfangs-/Endzeilen aller 118 Anwendungen untersucht. Es gibt weitere Kürzungsmöglichkeiten. Sie zerfallen in (R) kürzere Elementbeweise mit derselben Teilmengenregel und (S) noch kürzere Anwendungen bereits vorhandener Mengensätze. Begründungs- und Entladungsfehler stehen separat unter (F); notwendige zusätzliche Zeilen sind keine Einsparung.

| Band | Vorhandene Regelanwendungen | Befund |
|---|---:|---|
| 01 | 0 | Noch keine Mengen-/Teilmengenbeweise; die Regel aus B03 ist hier nicht verfügbar. |
| 02 | 0 | Logische Regeln und ihre Beweise; keine Teilmengenfolgerung. |
| 03 | 54 | Vier unmittelbare Kürzungen R1–R4; fünf weitere Satzanwendungen S1–S5; Fehler F1–F3. |
| 04 | 1 | Typisierungsbeweis durch Aussonderung verkürzbar (S6). |
| 05 | 32 | S7–S10; mehrere Abhängigkeitsfehler und zwei nicht entladene Existenzzeugen (F4–F7). |
| 06 | 2 | Keine weitere begründete Kürzung durch den Regelabschluss; F8 korrigiert die Annahmenliste. |
| 07 | 2 | Die beiden Elementbeweise benötigen ihre Zwischenschritte; insbesondere liegt der Faserfilter zunächst in U×V, nicht definitionsgemäß in K. |
| 08 | 8 | S11–S12; sonst Gleichheit/Transport oder bereits einzeilige Regelabschlüsse. |
| 09 | 0 | Teilmengen werden aus Reflexivität, Aussonderung, Graphentypisierung und Produktmonotonie übernommen. Kein übersehener lokaler Teilmengenabschluss. |
| 10 | 10 | Vier sichere Anwendungen früherer Mengensätze S13–S16. Nichtaktive ältere Nachfolgerbeweise wurden nicht mitgezählt. |
| 11 | 6 | Trägerinklusion einer Äquivalenzklasse S17. Die übrigen fünf Regelabschlüsse sind bereits direkt. |
| 12 | 1 | Hauptfilter S18. |
| 13 | 2 | Obere/untere Schrankenmengen S19–S20. |

Die Tabellen geben konkrete, bereits fachlich geprüfte Alternativen an. Sie sind keine Behauptung, dass jeder Beweis durch beliebige weitere Umorganisation global auf seine minimale Länge gebracht wurde.

## R: Kürzere Elementbeweise mit unveränderter Regelanwendungszahl

`A` bezeichnet eine lokale/äußere Annahme. Die Zahl vor einem Schritt ist seine neue Beweiszeilennummer. In allen vier Fällen ist die lokale Elementvariable frisch; sie kommt weder frei in den Mengenparametern noch in den übrigen offenen Annahmen vor. Alle verwendeten Elementhilfssätze stehen schon vor dem jeweiligen Zielbeweis.

| Nr. | Aktueller Satz und Quelle | Zeilen | Vollständige neue Ableitung |
|---|---|---:|---|
| R1 | **3.7.3.7**, `{x∈A | P(x)}⊆A`; `Bd. 03 - Mengenlehre.tex:933–938` | 4→3 | 1. `z∈{x∈A | P(x)}` A. 2. `z∈A` durch 3.7.3.1 aus 1. 3. `{x∈A | P(x)}⊆A` durch `SubsetIntroductionRule([1]⋮2)`. |
| R2 | **3.10.2.10**, `A∩B⊆A`; `Bd. 03 - Mengenlehre.tex:1872–1879` | 6→3 | 1. `z∈A∩B` A. 2. `z∈A` durch 3.10.2.1 aus 1. 3. `A∩B⊆A` durch die Regel `[1]⋮2`. |
| R3 | **3.10.2.11**, `A∩B⊆B`; `Bd. 03 - Mengenlehre.tex:1882–1889` | 6→3 | 1. `z∈A∩B` A. 2. `z∈B` durch 3.10.2.2 aus 1. 3. `A∩B⊆B` durch die Regel `[1]⋮2`. |
| R4 | **3.10.2.14**, „Teilmengen im Durchschnitt“; `Bd. 03 - Mengenlehre.tex:1916–1931` | 8→7 | 1. `A⊆B` A. 2. `A⊆C` A. 3. `z∈A` A. 4. `z∈B` durch Teilmengenelimination (1,3). 5. `z∈C` durch Teilmengenelimination (2,3). 6. `z∈B∩C` durch den früheren Satz `x∈A,x∈B ⊢ x∈A∩B` aus (4,5). 7. `A⊆B∩C` durch die Regel `[3]⋮6`, abhängig von 1,2. |

Diese vier voneinander unabhängigen Änderungen sparen **acht Zeilen**, ohne zusätzliche Regelanwendungen. Für R2 existiert sogar eine zweizeilige Alternative über die Schnittdefinition und 3.7.3.8; dann entfällt dort die Regelanwendung. Diese Alternative darf nicht zusätzlich zu R2 gezählt werden.

## S: Vorhandene Mengensätze sind kürzer als ein neuer Elementbeweis

In diesen Alternativen entstehen keine neuen freien Elementvariablen und keine lokalen Annahmen, die entladen werden müssten. Angegebene äußere Voraussetzungen und alle benannten Hilfssätze bleiben erhalten. Unbenutzte äußere Voraussetzungen können im Satz und in der Tabelle stehen bleiben; daraus entsteht keine unerlaubte Entladung.

Wiederkehrendes Schema **Aussonderung**: Aus `L={x∈H | P(x)}` folgt `L⊆H` unmittelbar durch den schon in B03 vorhandenen Satz **3.7.3.8**, Schlüssel `A=\{x\in B\mid P(x)\}\vdash A\subseteq B`. Dieser Satz steht vor sämtlichen folgenden Anwendungen. Für die bereits wörtlich als Aussonderung geschriebene Menge genügt 3.7.3.7.

| Nr. | Aktueller Satz / genaue Quelle | Zeilen | Neue Ableitung bzw. Ersatzblock |
|---|---|---:|---|
| S1 | **3.5.3.8**, „Rechtsverträglichkeit von ⊆ und =“; `Bd. 03 - Mengenlehre.tex:489–498` | 5→3 | 1. `A⊆B` A. 2. `B=C` A. 3. `A⊆C` durch Gleichheitsersetzung `=E(2,1)`. Ein Elementbeweis mit Teilmengenregel wäre länger. |
| S2 | **3.12.18**, `A⊆C ⊢ A\B⊆C`; `Bd. 03 - Mengenlehre.tex:3291–3297` | 5→3 | 1. `A⊆C` A. 2. `A\B⊆A` durch 3.12.16. 3. `A\B⊆C` durch Transitivität (2,1). Behebt zugleich F1. |
| S3 | **3.13.3.56(H2)**, „Zweite Inklusion“, Schlüssel `UnionWithRelativeRemainderBackward`; `Bd. 03 - Mengenlehre.tex:4513–4530` | 9→3 | 1. `M⊆H` A. 2. `H\M⊆H` durch Differenzinklusion. 3. `M∪(H\M)⊆H` durch den schon vorher bewiesenen `UnionSubsetCommonSuperset` aus (1,2). |
| S4 | **3.16.3.7**, `A⊆B, a∈P(A) ⊢ a∈P(B)`; `Bd. 03 - Mengenlehre.tex:5285–5292` | 5→4 | 1–3 unverändert: beide Annahmen und `P(A)⊆P(B)` durch Monotonie. 4. `a∈P(B)` durch Teilmengenelimination (3,2). Die zusätzliche Allquantorzeile entfällt. Das ist Elimination, nicht Einführung. |
| S5 | **3.16.4.2**, „Jedes boolesche Intervall ist ein Mengensystem“, `BooleanSetIntervalIsSetSystem`; `Bd. 03 - Mengenlehre.tex:5370–5387` | 6→3 | 1. `I[P,Q]={K∈P(Q) | P⊆K}` durch `BooleanSetIntervalDef`. 2. `I[P,Q]⊆P(Q)` durch Aussonderung (1). 3. `SetSys(I[P,Q];Q)` durch `SetSystemOverDef` (2). |
| S6 | **4.2.1.9**, „Typisierung der strikten Obermengenrelation“; `Bd. 04 - Totale Relationen.tex:266–281` | 6→3 | 1. `B⊆P(M)` A. 2. `StrictSupRel(B)={(x,y)∈B×B | x⊂y}` durch ihre Definition (1). 3. `StrictSupRel(B)⊆B×B` durch Aussonderung (2). |
| S7 | **5.2.4.9(H2)**, „Teilmengenrichtung {F(x)}⊆F[{x}]“; `Bd. 05 - Funktionen.tex:815–832` | 11→6 | 1. `x∈A` A. 2. `F:A→B` A. 3. `{x}⊆A` durch Einermengeninklusion (1). 4. `x∈{x}` durch den Einermengensatz. 5. `F(x)∈F[{x}]` durch den früheren Satz `C⊆A,F:A→B,x∈C ⊢ F(x)∈F[C]` aus (3,2,4). 6. `{F(x)}⊆F[{x}]` durch Einermengeninklusion (5). Der benannte H2 bleibt bestehen. |
| S8 | **5.2.5.4**, „Urbilder liegen im Definitionsbereich“; `Bd. 05 - Funktionen.tex:1299–1317` | 7→4 | 1. `F:A→B` A. 2. `C⊆B` A. 3. `F⁻¹[C]={x∈A | F(x)∈C}` durch Urbilddefinition (1,2). 4. `F⁻¹[C]⊆A` durch Aussonderung (3). |
| S9 | **5.2.5.9**, „Urbild eines Durchschnitts liegt im Durchschnitt der Urbilder“; `Bd. 05 - Funktionen.tex:1569–1593` | 13→8 | Zeilen 1–7 unverändert: Voraussetzungen, `C∩D⊆C,D` und daraus `F⁻¹[C∩D]⊆F⁻¹[C]`, `F⁻¹[C∩D]⊆F⁻¹[D]`. Neue Zeile 8: `F⁻¹[C∩D]⊆F⁻¹[C]∩F⁻¹[D]` durch 3.10.2.14 aus (6,7), abhängig von 1,2,3. Der ganze erneute Elementbeweis entfällt; zugleich verschwinden seine falschen Annahmenlisten. |
| S10 | **5.3.3.18**, „Spurmengen liegen in der Potenzmenge des Definitionsbereichs“, `TraceSetInPower`; `Bd. 05 - Funktionen.tex:4085–4103` | 6→4 | 1. `F:A→P(B)` A. 2. `b∈B` A. 3. `{x∈A | b∈F(x)}⊆A` durch 3.7.3.7. 4. Dieselbe Menge gehört zu `P(A)` durch die Potenzmengencharakterisierung (3). |
| S11 | **8.2.2.1(H2)**, „Teilmengenrichtung B⊆F[A]“; `Bd. 08 - Bijektive Funktionen.tex:236–270` | 15→5 | 1. `F:A bij B` A. 2. `F:A sur B` durch Bijektionsdefinition (1). 3. `F:A→B` durch Bijektionsdefinition (1). 4. `F[A]=B` durch den früheren B07-Hilfssatz `SurjectiveImageEqualsCodomain` aus (3,2). 5. `B⊆F[A]` durch `A=B ⊢ B⊆A` (4). H1, H2 und Hauptsatz bleiben erhalten; kein Vorwärtsverweis nach B08. |
| S12 | **8.3.6.4**, „Jede Kernfamilie liegt in der Potenzmenge ihres Trägers“, `CoreFamilySubsetPowerset`; `Bd. 08 - Bijektive Funktionen.tex:2932–2943` | 4→2 | 1. `CoreFamily(P,A)={H∈P(P∪A) | P⊆H}` durch `CoreFamilyDef`. 2. `CoreFamily(P,A)⊆P(P∪A)` durch Aussonderung (1). |
| S13 | **10.2.4.9**, „Teilmengen einer Nachfolgermenge ohne neues Element“; `Bd. 10 - Natürliche Zahlen.tex:448–473` | 15→6 | 1. `n∈N` A. 2. `B⊆Succ(n)` A. 3. `n∉B` A. 4. `Succ(n)=n∪{n}` durch den früheren Nachfolgersatz (1). 5. `B⊆n∪{n}` durch `=E(4,2)`. 6. `B⊆n` durch den B03-Satz `SubsetAdjoinWithoutPoint` aus (5,3). |
| S14 | **10.2.4.10(H2)**, „Rückrichtung“; `Bd. 10 - Natürliche Zahlen.tex:515–539` | 12→6 | 1–3 die vorhandenen Annahmen `n∈N`, `B⊆Succ(n)`, `n∈B`. 4. `B∩n⊆B` durch Schnittinklusion. 5. `{n}⊆B` durch Einermengeninklusion (3). 6. `(B∩n)∪{n}⊆B` durch `UnionSubsetCommonSuperset` (4,5). Die Schlusszeile benötigt nur Annahme 3; die weiteren äußeren Voraussetzungen dürfen erhalten bleiben. |
| S15 | **10.4.6.27**, „Teilmengen eines Nachfolger-Anfangsabschnitts ohne Endpunkt“, `PeanoNatSegSubsetAddOneWithoutEndpoint`; `Bd. 10 - Natürliche Zahlen.tex:12518–12539` | 12→6 | 1. `n∈N` A. 2. `B⊆NatSeg(n+1)` A. 3. `n∉B` A. 4. `NatSeg(n+1)=NatSeg(n)∪{n}` durch den bereits früheren Satz `PeanoNatSegAddOne` (1). 5. `B⊆NatSeg(n)∪{n}` durch `=E(4,2)`. 6. `B⊆NatSeg(n)` durch `SubsetAdjoinWithoutPoint` (5,3). |
| S16 | **10.4.6.28(H2)**, „Rückrichtung“; `Bd. 10 - Natürliche Zahlen.tex:12580–12600` | 12→6 | 1–3 die vorhandenen Voraussetzungen. 4. `B∩NatSeg(n)⊆B` durch Schnittinklusion. 5. `{n}⊆B` durch Einermengeninklusion (3). 6. `(B∩NatSeg(n))∪{n}⊆B` durch `UnionSubsetCommonSuperset` (4,5). |
| S17 | **11.4.2.2(H1)**, „Teilmenge des Grundbereichs“, `EqClassSubsetCarrierForQuotient`; `Bd. 11 - Äquivalenzrelationen.tex:1122–1135` | 5→4 | 1. `EqRel(A,~)` A. 2. `x∈A` A. 3. `[x]={y∈A | x~y}` durch `EqClassDef` (1,2). 4. `[x]⊆A` durch Aussonderung (3). |
| S18 | **12.3.1.1**, „Hauptfilter liegen im Ordnungsträger“, `PrincipalFilterSubsetCarrier`; `Bd. 12 - Halbordnungen.tex:623–635` | 4→2 | 1. `PrincipalFilter(A,≤,j)={x∈A | j≤x}` durch `PrincipalFilter`. 2. `PrincipalFilter(A,≤,j)⊆A` durch Aussonderung (1). Die Definition fordert weder `j∈A` noch eine zusätzliche Ordnungsannahme. |
| S19 | **13.2.1.4**, „Die obere Schrankenmenge liegt im Träger“, `UpperBoundSetSubsetCarrier`; `Bd. 13 - Schranken, Infima und Suprema.tex:150–164` | 5→3 | 1. `T⊆A` A. 2. `UB(T)={u∈A | ∀x∈T(x≤u)}` durch `UpperBoundSet` (1). 3. `UB(T)⊆A` durch Aussonderung (2). Die Δ-Voraussetzung der partiellen Ordnung bleibt bestehen. |
| S20 | **13.2.1.8**, „Die untere Schrankenmenge liegt im Träger“, `LowerBoundSetSubsetCarrier`; `Bd. 13 - Schranken, Infima und Suprema.tex:225–239` | 5→3 | 1. `T⊆A` A. 2. `LB(T)={u∈A | ∀x∈T(u≤x)}` durch `LowerBoundSet` (1). 3. `LB(T)⊆A` durch Aussonderung (2), bei unveränderter Δ-Voraussetzung. |

Diese zwanzig Alternativen sparen zusammen **78 Zeilen**, wenn sie alle gewählt werden. Mit R1–R4 sind es **86 zusätzliche mögliche Kürzungszeilen in 24 Beweisen/Teilbeweisen**. Das ist ein Vorschlag, keine bereits erfolgte Änderung. Die nachstehend nötigen Reparaturzeilen und die optionale zweizeilige R2-Alternative sind in dieser Zahl nicht verrechnet.

## F: Begründungs- und Entladungsfehler, getrennt von Kürzungen

### F1: Lokale Annahme bleibt in der Schlussliste stehen

**3.12.18**, `Bd. 03 - Mengenlehre.tex:3297`: Die Regel `[2]⋮4` entlädt `x∈A\B` aus Zeile 2. Die Schlusszeile muss nur von **1** abhängen, nicht von `1,2`. Minimalreparatur: unverändert fünf Zeilen, lediglich Schlussliste `{1}`. S2 ist die zusätzlich mögliche dreizeilige Alternative.

### F2: Adjunktionsgleichheit mit falschen Annahmenlisten und impliziter Inklusion

**3.13.3.9**, `A∪{a}=A ⇔ a∈A`, `Bd. 03 - Mengenlehre.tex:3762–3799`:

- Vorwärtsrichtung: Zeile 3 `a∈A` hängt von Annahme 1 ab; sie ist derzeit leer markiert.
- Rückrichtung: Die tatsächliche Zeile 4 ist als Annahme `3` markiert. Der Regelabschluss in tatsächlicher Zeile 9 hängt weiterhin von `a∈A` (1) ab; die leere Liste ist falsch.
- Die aktuelle Zeile 10 zitiert `z∈A ⊢ z∈A∪B` unmittelbar für `A⊆A∪{a}`. Dieses Elementlemma ist keine Teilmengenregel. Der allgemeine Satz `A⊆A∪B` steht erst später in B03 und wäre hier ein neuer Vorwärtsverweis.
- Die abschließende Antisymmetrie sollte den Satz mit **zwei** Voraussetzungen `A⊆B,B⊆A ⊢ A=B` zitieren, nicht die Variante mit einer Konjunktion ohne deren Einführung.

Gültige vollständige Rückrichtung, **13 statt bisher 11 Zeilen**:

| Zeile | Offene Annahmen | Formel | Grund |
|---:|---|---|---|
| 1 | 1 | `a∈A` | A |
| 2 | 2 | `x∈A∪{a}` | A |
| 3 | 2 | `x∈A ∨ x∈{a}` | Vereinigungskriterium (2) |
| 4 | 4 | `x∈A` | A |
| 5 | 5 | `x∈{a}` | A |
| 6 | 5 | `x=a` | Einermengenkriterium (5) |
| 7 | 1,5 | `x∈A` | früherer Satz 3.4.1.2 `a=b,b∈C ⊢ a∈C` (6,1) |
| 8 | 1,2 | `x∈A` | ∨E(3,4,4,5,7) |
| 9 | 1 | `A∪{a}⊆A` | Teilmengenregel `[2]⋮8` |
| 10 | 10 | `x∈A` | A |
| 11 | 10 | `x∈A∪{a}` | früheres Elementlemma (10) |
| 12 | – | `A⊆A∪{a}` | Teilmengenregel `[10]⋮11` |
| 13 | 1 | `A∪{a}=A` | Antisymmetrie mit zwei Voraussetzungen (9,12) |

`x` ist frisch gegenüber der einzigen übrigen Annahme `a∈A`; beide lokalen Elementannahmen sind sauber entladen. Zusammen mit der dreizeiligen Vorwärtsrichtung: **14→16 Zeilen**, eine zusätzliche Regelanwendung. Dies ist eine Reparatur, keine Einsparung.

### F3: Zwei Elementhilfssätze werden als Mengeninklusionen zitiert

**3.16.3.3**, `P(∅)={∅}`, `Bd. 03 - Mengenlehre.tex:5226–5257`: H1 und H2 behaupten ausdrücklich nur Elementfolgerungen. Im Schlussblock Zeilen 5251/5253 fehlen deshalb lokale Annahme und Regelabschluss. Die Aussagen von H1 und H2 bleiben erhalten. H2 sollte zusätzlich wie unten ausgeschrieben korrigiert werden.

Vollständiger gültiger neuer Schlussblock, **7 statt 3 Zeilen**:

1. `x∈P(∅)` — A, Annahme 1.
2. `x∈{∅}` — H1(1), abhängig von 1.
3. `P(∅)⊆{∅}` — Regel `[1]⋮2`, keine offene Annahme.
4. `x∈{∅}` — A, Annahme 4.
5. `x∈P(∅)` — H2(4), abhängig von 4.
6. `{∅}⊆P(∅)` — Regel `[4]⋮5`, keine offene Annahme.
7. `P(∅)={∅}` — Antisymmetrie (3,6).

`x` ist frisch; keine weiteren offenen Annahmen. Würden H1 (4 Zeilen) und H2 (5 Zeilen) unverändert bleiben, wären es 12→16 Gesamtzeilen. H2 verwendet aktuell jedoch außerdem `=E(2,3)` mit `x=∅` und `∅⊆∅` in der falschen Ersetzungsrichtung. Der vollständig gültige, zugleich kürzere H2 lautet:

1. `x∈{∅}` — A.
2. `x=∅` — Einermengenkriterium (1).
3. `x⊆∅` — früherer Satz `A=B ⊢ A⊆B` (2).
4. `x∈P(∅)` — Potenzmengencharakterisierung (3).

Mit H1 unverändert, diesem H2 und dem siebenzeiligen Schlussblock ergibt die **vollständige Reparatur 12→15 Gesamtzeilen** und zwei zusätzliche Regelanwendungen. Der Gewinn einer Zeile in H2 ist ausschließlich hier verrechnet, nicht zusätzlich unter R/S.

### F4: Abgeleitete Zeilen werden als offene Annahmen geführt

**5.2.5.3(H1/H2)**, „Urbild einer Einermenge“, `Bd. 05 - Funktionen.tex:1240–1253` und `1273–1279`: Zeile 3 ist die aus Annahme 2 hergeleitete Inklusion `{y}⊆B`, keine neue Annahme. Deshalb müssen die dortigen Listen `1,3` zu `1,2` und `1,3,4` zu `1,2,4` werden. Die vorhandenen zwölf Zeilen je Richtung und der Regelabschluss `[4]⋮11` sind nach dieser Listenreparatur gültig. Die lokale Variable `x` steht nicht frei in den äußeren Voraussetzungen `F:A→B`, `y∈B`.

### F5: Urbildschnitt — erneut falsche Abhängigkeitslisten

**5.2.5.9**, Zeilen `1587–1591`: Die dort als Annahmen genannten 6 und 7 sind bereits abgeleitete Inklusionen. Korrekt sind für die tatsächlichen Zeilen 9–12: `{1,2,8}`, `{1,3,8}`, `{1,2,3,8}`, `{1,2,3,8}`. Die Schlussliste `{1,2,3}` ist dann richtig. Keine zusätzlichen Zeilen; S9 beseitigt den ganzen überflüssigen Block.

**5.2.5.10**, `Bd. 05 - Funktionen.tex:1632`: Die Abhängigkeitsliste der tatsächlichen Zeile 17 muss `{1,3}` sein, nicht `{1,15}`, weil 15 aus Annahme 3 folgt. Keine zusätzliche Zeile.

**5.2.5.11(H1)**, `Bd. 05 - Funktionen.tex:1660–1663`: Die Endzeile des Elementbeweises muss von `{1,2,3,4}` abhängen, nicht von `{1,2,3,6,7}`; 6 und 7 folgen beide aus Annahme 4. Danach ist der vorhandene Abschluss `[4]⋮8` mit Liste `{1,2,3}` gültig. Neun Zeilen bleiben neun.

### F6: Zwei nicht entladene Existenzzeugen im Bild der Einschränkung

**5.3.2.16(H1/H2)**, „Bild der Einschränkung“, `Bd. 05 - Funktionen.tex:2836–2853` und `2861–2879`:

H1: Aktuell wird nach der Zeugenannahme 6 aus `∃x∈C(y=F|C(x))` direkt bis `y∈F[C]` (Zeile 12, Liste `1,2,6`) gerechnet. Die anschließend verwendete Teilmengenregel darf Zeugenannahme 6 nicht mit entladen.

Minimaler gültiger Ersatz des Endes:

12. `y∈F[C]` — vorhandene Zeile, abhängig von 1,2,6.
13. `y∈F[C]` — `∃E(5,6,12)`, abhängig von **1,2,4**.
14. `(F|C)[C]⊆F[C]` — Regel `[4]⋮13`, abhängig von **1,2**.

H2 entsprechend:

13. `y∈(F|C)[C]` — vorhandene Zeile, abhängig von 1,2,6.
14. `y∈(F|C)[C]` — `∃E(5,6,13)`, abhängig von **1,2,4**.
15. `F[C]⊆(F|C)[C]` — Regel `[4]⋮14`, abhängig von **1,2**.

Der Existenzzeuge `x` kommt in der jeweiligen Endformel nicht frei vor. Nach seiner Entladung ist auch `y` frisch gegenüber den übrigen Annahmen `C⊆A`, `F:A→B`. **H1: 13→14, H2: 14→15 Zeilen**, zusammen zwei notwendige Zusatzzeilen; keine neue Regelanwendung.

### F7: Weiterer Listenfehler im unmittelbaren Umfeld eines Regelabschlusses

**5.2.4.16**, „Das Bild einer Teilmenge liegt im Zielbereich“, `Bd. 05 - Funktionen.tex:1080`: Die tatsächliche Zeile 8 `x∈A` hängt von **1,5** ab, nicht von `1,6`; 6 ist die aus Zeugenannahme 5 gewonnene Aussage `x∈C`. Die Existenzelimination in Zeile 11 und der Regelabschluss in Zeile 12 sind vorhanden. Keine zusätzliche Zeile nötig. Wichtig: Der behauptete Bildmengensatz lässt sich hier nicht einfach durch Aussonderung ersetzen, da die aktuelle Bilddefinition eine Iota-Definition über ein unbeschränktes Existenzkriterium ist; eine Zielbereichsinklusion muss erst bewiesen werden.

### F8: Bildschnitt bei Injektionen lässt Grundannahmen verschwinden

**6.2.2.5(H2)**, `Bd. 06 - Injektive Funktionen.tex:334–337`: Die tatsächliche Zeile 8 hat Liste **1,2,3,4** statt `1,2,3,6,7`. Der Regelabschluss `[4]⋮8` muss die Liste **1,2,3** tragen, nicht nur `1`. Äußere Voraussetzungen `F:M inj N`, `A⊆M`, `B⊆M` bleiben nötig; `y` ist frisch gegenüber ihnen. Minimalreparatur unverändert neun Zeilen.

### Nicht als Fehler zu werten

In `RemoveDisjointUnionSummandForward` (B03:4564), `CoreFamilyRemainder` (B08:3256) sowie B10:511, 12576 und 12599 werden zusätzliche, im Elementbeweis nicht gebrauchte **äußere** Voraussetzungen in der Schlussliste beibehalten. Das ist eine zulässige Abschwächung und nicht mit der unerlaubten Entladung einer lokalen Annahme zu verwechseln.

## Nicht doppelt gezählte Bilanz der ausgeschriebenen Alternativen

- R1–R4: 24→16 Zeilen, **−8**.
- S1–S20: 162→84 Zeilen, **−78**.
- F2 vollständig: 14→16, **+2**.
- F3 einschließlich korrigiertem H2: 12→15, **+3**.
- F6, beide Richtungen: 27→29, **+2**.
- Reine Listenreparaturen F1/F4/F5/F7/F8: **0** Zusatzzeilen; S2 und S9 werden bei F1/F5 nicht nochmals gezählt.

Damit ergeben die **konkret ausgeschriebenen**, miteinander verträglichen Änderungen insgesamt **239→160 Zeilen**, also **79 Zeilen netto weniger**, in 28 Beweisen/Teilbeweisen mit einer Zeilenzahländerung. Die zusätzliche zweizeilige Alternative zu R2 ist nicht eingerechnet. Keine dieser Änderungen wurde ausgeführt. Die Regelanwendungszahl würde in B01–B13 bei Wahl dieser gesamten Kombination von 118 auf 103 sinken: 18 erneute Elementbeweise werden durch schon vorhandene Mengensätze ersetzt, an den bisher impliziten Stellen kommen drei ausdrücklich begründete Anwendungen hinzu.

## Grenzen und begründete Nichtänderungen

- Die Begründung der neuen Regel selbst in B03:242–246 muss weiterhin über Implikations-/Allquantoreinführung und die Teilmengendefinition laufen. Eine Anwendung der Regel im eigenen Beweis wäre zirkulär.
- Die Definitionsverweise bei B03:348, 380, 384, 4813 und 5290 sind Eliminationen, keine übersehenen Einführungen; nur bei 5290 ergibt die vorhandene spezialisierte Elimination tatsächlich die in S4 angegebene Zeilenersparnis. Die Antisymmetrie in B03:403–420 ist eine kurze Äquivalenzkette; zwei neue lokale Inklusionsbeweise wären länger.
- Bestehende direkte Gleichheits-, Reflexivitäts-, Monotonie- und Transitivitätsschritte wurden nicht allein zur Vergrößerung der Regelanwendungszahl durch Elementbeweise ersetzt.
- B07-Faserfilter: `Phi(K)` ist eine Aussonderung aus `U×V` mit einer zusätzlichen Bedingung über die Projektionen. Die Behauptung `Phi(K)⊆K` folgt daher nicht schon aus der allgemeinen Aussonderungsinklusion. Die Rekonstruktion `p=(pi1(p),pi2(p))` ist erforderlich; kein dreizeiliger scheinbarer Aussonderungsbeweis.
- B05-Bildmengen: Anders als die Urbilddefinition ist die Bilddefinition an der geprüften Stelle keine Aussonderung aus B. Die ausführliche Zeugenargumentation wurde deshalb nicht als triviale Aussonderungskürzung eingestuft.
- In B09 sind die beiden Produktmonotonien und anschließenden Transitivitätsschritte bereits Übernahmen allgemeiner Sätze. Ein erneuter Elementbeweis mit Paarzerlegung würde zusätzliche Zeilen und Zeugenannahmen erzeugen.
- Allquantorzeilen in B08 betreffen Gleichheits-/Transportkriterien (`F(x)∈T ↔ x∈S`) und in B10 die Abgeschlossenheit von Mengen bzw. Funktionswerten. Sie sind keine versteckten Aussagen `∀x∈M(x∈N)`, deren Schluss durch die Teilmengenregel ersetzt werden könnte.

## Reproduzierbare Arbeitsdaten

`early-scan.json` enthält die eigene bandweise Include-/Zeileninventur und die untersuchten Teilmengenzeilen. `early-rule-dependencies.json` enthält Anfangs-/Endformeln und die Annahmenlisten der 118 Regelanwendungen; Unterschiede zwischen mechanisch berechneten und angegebenen Listen wurden fachlich geprüft, zulässige Abschwächungen aussortiert. Ergänzend wurden die vom Hauptagenten erzeugten `coverage.json`, `subset-rows.json`, `applications.json`, `quantifier-rows.json` mit der aktuellen Quelle abgeglichen. Keine dieser Inventuren ersetzt die oben ausgeschriebenen fachlichen Prüfungen.
