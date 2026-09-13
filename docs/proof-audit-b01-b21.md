# Beweisinventur B01–B21

Stand: 6. September 2026. Gegenstand sind sämtliche aktiven Banddateien B01–B21; Archivdateien gehören nicht zur aktiven Bandfolge. Die Tabellenbeweise wurden vollständig nach Sätzen, Schlussformeln, vorhandenen Teilen und mehrfachen Beweiszielen inventarisiert.

Die Aufteilung verwendet die vorhandenen `proofpart`-/`proofpartwide`-Makros. Fortlaufende Schrittnummern innerhalb desselben Beweises werden durch `setcounter` erhalten. Registrierte Teilresultate behalten ihre Formeln und Schlüssel; bei deren Unterteilung steht die Registrierung vor der abschließenden Zusammenführung.

| Band | Geprüfte Tabellenbeweise | Beweiszeilen | Aufgeteilte Beweise/Teile |
|---|---:|---:|---:|
| B01 | 0 | 0 | 0 |
| B02 | 272 | 2294 | 25 |
| B03 | 307 | 2379 | 11 |
| B04 | 10 | 70 | 2 |
| B05 | 131 | 1373 | 12 |
| B06 | 38 | 391 | 5 |
| B07 | 57 | 446 | 7 |
| B08 | 98 | 1303 | 11 |
| B09 | 25 | 263 | 2 |
| B10 | 411 | 4647 | 19 |
| B11 | 57 | 679 | 4 |
| B12 | 10 | 117 | 5 |
| B13 | 28 | 308 | 2 |
| B14 | 17 | 231 | 5 |
| B15 | 25 | 300 | 1 |
| B16 | 11 | 124 | 2 |
| B17 | 92 | 1420 | 1 |
| B18 | 66 | 741 | 8 |
| B19 | 40 | 1659 | 16 |
| B20 | 187 | 2176 | 12 |
| B21 | 59 | 829 | 5 |

Ergebnis: 1.941 Beweisblöcke mit 21.750 erfassten Beweiszeilen; 155 Beweise beziehungsweise bestehende Teile wurden sinnvoll untergliedert. B01 enthält keine Tabellenbeweise. Der maschinelle Vergleich vor/nach der Aufteilung bestätigt unveränderte Satzformeln, Beweiszeilenzahlen und tatsächliche Schrittnummerierung. `git diff --check` ist ohne Befund. Der Layout-/Gesamtbuild wird zentral durchgeführt.

## Geänderte Beweise und Teile

### B02

- [Kommutativgesetz für \(\lor\)](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L104): Hinrichtung; Rückrichtung; Zusammenführung.
- [$\vdash$](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L699): Negation der ersten Aussage; Negation der zweiten Aussage; Zusammenführung der Hinrichtung.
- [P \rightarrow Q \vdash P \leftrightarrow (P \land Q)](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L848): Hinrichtung; Rückrichtung; Zusammenführung.
- [P \rightarrow Q \vdash P \leftrightarrow (Q \land P)](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L872): Hinrichtung; Rückrichtung; Zusammenführung.
- [P\rightarrow Q\vdash (P\land Q)\leftrightarrow P](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L896): Rückrichtung; Hinrichtung; Zusammenführung.
- [P\rightarrow Q\vdash (Q\land P)\leftrightarrow P](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L922): Rückrichtung; Hinrichtung; Zusammenführung.
- [P \leftrightarrow (Q \land R), Q \rightarrow R \vdash P \leftrightarrow Q](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L1519): Hinrichtung; Rückrichtung; Zusammenführung.
- [Q\vdash (P\leftrightarrow Q\land R)\leftrightarrow (P\leftrightarrow R)](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L1673): Hinrichtung; Rückrichtung; Zusammenführung.
- [Halbaddierer bei zwei falschen Eingängen](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L2557): Summenbit; Übertragsbit; Zusammenführung.
- [Halbaddierer bei linkem wahren Eingang](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L2583): Summenbit; Übertragsbit; Zusammenführung.
- [Halbaddierer bei rechtem wahren Eingang](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L2606): Summenbit; Übertragsbit; Zusammenführung.
- [Halbaddierer bei zwei wahren Eingängen](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L2629): Summenbit; Übertragsbit; Zusammenführung.
- [Volladdierer bei \(000\)](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L3262): Summenbit; Übertragsbit; Zusammenführung.
- [Volladdierer bei \(100\)](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L3297): Summenbit; Übertragsbit; Zusammenführung.
- [Volladdierer bei \(010\)](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L3332): Summenbit; Übertragsbit; Zusammenführung.
- [Volladdierer bei \(001\)](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L3367): Summenbit; Übertragsbit; Zusammenführung.
- [Volladdierer bei \(110\)](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L3402): Summenbit; Übertragsbit; Zusammenführung.
- [Volladdierer bei \(101\)](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L3435): Summenbit; Übertragsbit; Zusammenführung.
- [Volladdierer bei \(011\)](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L3469): Summenbit; Übertragsbit; Zusammenführung.
- [Volladdierer bei \(111\)](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L3503): Summenbit; Übertragsbit; Zusammenführung.
- [\forall x(\neg Q(x)) \vdash P \leftrightarrow P \lor Q(a)](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L4474): Hinrichtung; Rückrichtung; Zusammenführung.
- [Eindeutige Existenz aus Existenz und Höchstens-eins](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L4670): Existenz; Eindeutigkeit; Eindeutige Existenz.
- [Beweis](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L4725): Existenz eines ersten Zeugen; Eindeutigkeit des zweiten Zeugen; Existenz mit eindeutigem zweiten Zeugen; Eindeutigkeit des ersten Zeugen; Geschachtelte eindeutige Existenz.
- [$\vdash$](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L4827): Wahrer Bedingungsfall; Falscher Bedingungsfall; Zusammenführung der Hinrichtung.
- [Wohldefiniertheit](../Bd.%2002%20-%20Theoreme%20der%20Logik.tex#L4913): Existenz; Eindeutigkeit; Eindeutige Existenz.

### B03

- [A\subseteq C\vdash \exists! R\,\bigl(R\subseteq C\land R=A\bigr)](../Bd.%2003%20-%20Mengenlehre.tex#L418): Existenz; Eindeutigkeit; Eindeutige Existenz.
- [\exists! O\forall x (x \not\in O)](../Bd.%2003%20-%20Mengenlehre.tex#L470): Existenz; Eindeutigkeit; Eindeutige Existenz.
- [Eindeutigkeit der Komprehension](../Bd.%2003%20-%20Mengenlehre.tex#L682): Existenz; Eindeutigkeit; Eindeutige Existenz.
- [\(\vdash\)](../Bd.%2003%20-%20Mengenlehre.tex#L1316): Ausschluss des ersten Gegenfalls; Ausschluss des zweiten Gegenfalls; Zusammenführung der Hinrichtung.
- [P(D)\vdash \exists! C\forall B(P(B)\rightarrow C= \{ x \in B \mid \forall A (P(A) \rightarrow x \in A) \})](../Bd.%2003%20-%20Mengenlehre.tex#L2051): Existenz; Eindeutigkeit; Eindeutige Existenz.
- [\{a\}=\{b,c\}\vdash a=b\land a=c](../Bd.%2003%20-%20Mengenlehre.tex#L2470): Gleichheit mit dem ersten Element; Gleichheit mit dem zweiten Element; Zusammenführung.
- [\{a,b\}=\{c,d\}\vdash (a=c\lor a=d)\land (b=c\lor b=d)](../Bd.%2003%20-%20Mengenlehre.tex#L2654): Zugehörigkeit des ersten Elements; Zugehörigkeit des zweiten Elements; Zusammenführung.
- [Negierte Mitgliedschaft im relativen Komplement](../Bd.%2003%20-%20Mengenlehre.tex#L2981): Hinrichtung; Rückrichtung; Zusammenführung.
- [Relatives Komplement ist involutiv](../Bd.%2003%20-%20Mengenlehre.tex#L3204): Erste Inklusion; Zweite Inklusion; Mengengleichheit.
- [Nichtzugehörigkeit zu beiden Summanden einer Vereinigung](../Bd.%2003%20-%20Mengenlehre.tex#L3498): Nichtzugehörigkeit zum ersten Summanden; Nichtzugehörigkeit zum zweiten Summanden; Zusammenführung.
- [Überdeckung einer Potenzmenge an einem adjungierten Punkt](../Bd.%2003%20-%20Mengenlehre.tex#L5488): Erste Inklusion; Zweite Inklusion; Mengengleichheit.

### B04

- [Totale Relation](../Bd.%2004%20-%20Totale%20Relationen.tex#L177): Trägerrelation; Totalität; Zusammenführung.
- [Totalität der strikten Obermengenrelation](../Bd.%2004%20-%20Totale%20Relationen.tex#L288): Trägerrelation; Totalität; Zusammenführung.

### B05

- [F\colon A\to B \vdash \TotRel{F,A,B}](../Bd.%2005%20-%20Funktionen.tex#L110): Trägerrelation; Totalität; Zusammenführung.
- [Eindeutigkeit des Definitionsbereichs einer Funktion](../Bd.%2005%20-%20Funktionen.tex#L177): Erste Inklusion; Zweite Inklusion; Gleichheit der Definitionsbereiche.
- [Eindeutigkeit des Funktionswertes](../Bd.%2005%20-%20Funktionen.tex#L227): Existenz; Eindeutigkeit; Eindeutige Existenz.
- [Graph eines Funktionensymbols ist eine Funktion](../Bd.%2005%20-%20Funktionen.tex#L1826): Trägerrelation; Funktionale Eindeutigkeit; Totalität; Zusammenführung.
- [Ein geordnetes Paar als Funktionsgraph](../Bd.%2005%20-%20Funktionen.tex#L2151): Trägerrelation; Existenz der Werte; Eindeutigkeit der Werte; Zusammenführung zur Funktion.
- [y\in B\vdash x\in\Fib_F(y)\leftrightarrow x\in A\land F(x)=y](../Bd.%2005%20-%20Funktionen.tex#L2534): Hinrichtung; Rückrichtung; Zusammenführung.
- [Gleichheitskriterium für Funktionseinschränkungen](../Bd.%2005%20-%20Funktionen.tex#L2737): Hinrichtung; Rückrichtung; Zusammenführung.
- [Verkleinerung der Zielmenge](../Bd.%2005%20-%20Funktionen.tex#L2934): Trägerrelation im kleineren Zielbereich; Funktionale Eindeutigkeit; Totalität; Zusammenführung.
- [Punkt-Erweiterung](../Bd.%2005%20-%20Funktionen.tex#L4309): Wert am neuen Punkt; Werte auf dem bisherigen Bereich; Zusammenführung.
- [Leere Relation ist eine Funktion](../Bd.%2005%20-%20Funktionen.tex#L4385): Trägerrelation; Funktionale Eindeutigkeit; Totalität; Zusammenführung.
- [Eindeutige Existenz einer Funktion aus $\varnothing$](../Bd.%2005%20-%20Funktionen.tex#L4439): Existenz; Eindeutigkeit; Eindeutige Existenz.
- [Vereinigung einer überdeckenden Teilmengenfamilie](../Bd.%2005%20-%20Funktionen.tex#L4520): Erste Inklusion; Zweite Inklusion; Mengengleichheit.

### B06

- [Verkleinerung der Zielmenge erhält Injektivität](../Bd.%2006%20-%20Injektive%20Funktionen.tex#L384): Funktionstyp im kleineren Zielbereich; Injektivität; Zusammenführung.
- [Erweiterung der Zielmenge erhält Injektivität](../Bd.%2006%20-%20Injektive%20Funktionen.tex#L414): Funktionstyp im größeren Zielbereich; Injektivität; Zusammenführung.
- [Einschränkung einer injektiven Funktion](../Bd.%2006%20-%20Injektive%20Funktionen.tex#L471): Funktionstyp; Injektivität; Zusammenführung.
- [Leere Relation ist injektiv](../Bd.%2006%20-%20Injektive%20Funktionen.tex#L1114): Funktionstyp; Injektivität; Zusammenführung.
- [Adjunktionsabbildung ist injektiv](../Bd.%2006%20-%20Injektive%20Funktionen.tex#L1251): Funktionstyp; Injektivität; Zusammenführung.

### B07

- [Korestriktion auf das Bild als surjektive Funktion](../Bd.%2007%20-%20Surjektive%20Funktionen.tex#L139): Trägerrelation; Funktionale Eindeutigkeit; Totalität; Surjektivität; Zusammenführung.
- [F\colon A\inj B \dsep a_0\in A \vdash \Gsurjfrominj{F}{a_0}\colon B\to A](../Bd.%2007%20-%20Surjektive%20Funktionen.tex#L689): Trägerrelation; Totalität; Funktionale Eindeutigkeit; Zusammenführung.
- [F\colon A\inj B \dsep a_0\in A \vdash \Gsurjfrominj{F}{a_0}\colon B\sur A](../Bd.%2007%20-%20Surjektive%20Funktionen.tex#L731): Funktionstyp; Surjektivität; Zusammenführung.
- [Erste Projektion als surjektive Funktion](../Bd.%2007%20-%20Surjektive%20Funktionen.tex#L1237): Funktionstyp; Surjektivität; Zusammenführung.
- [Zweite Projektion als surjektive Funktion](../Bd.%2007%20-%20Surjektive%20Funktionen.tex#L1292): Funktionstyp; Surjektivität; Zusammenführung.
- [\DisjFam(\Fib_F[B])](../Bd.%2007%20-%20Surjektive%20Funktionen.tex#L1373): Nichtleerheit der Familienglieder; Paarweise Disjunktheit; Zusammenführung.
- [Leere Relation ist surjektiv auf $\varnothing$](../Bd.%2007%20-%20Surjektive%20Funktionen.tex#L1594): Funktionstyp; Surjektivität; Zusammenführung.

### B08

- [F\colon A\inj B\dsep F\colon A\sur B \vdash F\colon A\bij B](../Bd.%2008%20-%20Bijektive%20Funktionen.tex#L110): Injektivität; Surjektivität; Bijektivität.
- [Eindeutigkeit des Urbildes bei Bijektivität](../Bd.%2008%20-%20Bijektive%20Funktionen.tex#L175): Existenz; Eindeutigkeit; Eindeutige Existenz.
- [\(\Id_A\) als bijektive Funktion](../Bd.%2008%20-%20Bijektive%20Funktionen.tex#L397): Funktionstyp; Injektivität; Surjektivität; Bijektivität.
- [Einschränkung auf ein Urbild als bijektive Funktion](../Bd.%2008%20-%20Bijektive%20Funktionen.tex#L431): Injektivität der Einschränkung; Surjektivität der Einschränkung; Bijektivität.
- [\(F^{-1}\) als bijektive Funktion](../Bd.%2008%20-%20Bijektive%20Funktionen.tex#L898): Funktionstyp; Injektivität; Surjektivität; Bijektivität.
- [Die Komposition als bijektive Funktion](../Bd.%2008%20-%20Bijektive%20Funktionen.tex#L1041): Injektivität der Komposition; Surjektivität der Komposition; Bijektivität.
- [F\circ G = \Id_A\dsep G\circ F =\Id_B \vdash F\colon B\bij A](../Bd.%2008%20-%20Bijektive%20Funktionen.tex#L1359): Surjektivität; Injektivität; Bijektivität.
- [F\circ G = \Id_A\dsep G\circ F =\Id_B \vdash G\colon A\bij B](../Bd.%2008%20-%20Bijektive%20Funktionen.tex#L1390): Surjektivität; Injektivität; Bijektivität.
- [Induzierte Potenzmengenabbildung einer Bijektion](../Bd.%2008%20-%20Bijektive%20Funktionen.tex#L1513): Injektivität; Surjektivität; Bijektivität.
- [Bijektivität der induzierten Potenzmengenabbildung erzwingt Bijektivität](../Bd.%2008%20-%20Bijektive%20Funktionen.tex#L1697): Injektivität; Surjektivität; Bijektivität.
- [Bijektivität außerhalb einer Teilmengenfamilie erzwingt Bijektivität der Grundabbildung](../Bd.%2008%20-%20Bijektive%20Funktionen.tex#L2259): Injektivität; Surjektivität; Bijektivität.

### B09

- [Eindeutige Existenz eines Auswahlelements in $X$](../Bd.%2009%20-%20Auswahlprinzip.tex#L418): Existenz; Eindeutigkeit; Eindeutige Existenz.
- [Verkleben ausgewählter Faserbijektionen](../Bd.%2009%20-%20Auswahlprinzip.tex#L987): Konstruktion und Funktionstyp; Verträglichkeit mit den Retraktionen; Fortsetzung auf den Retraktionsbildern; Injektivität; Surjektivität; Bijektivität und Zusammenführung.

### B10

- [\Induktiv(A),\, \Induktiv(B)\vdash \Induktiv(A\cap B)](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L116): Nullaufnahme; Nachfolgerabschluss; Induktivität.
- [Mitgliedschaft genau echte Teilmenge](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L2424): Hinrichtung; Rückrichtung; Zusammenführung.
- [Elemente einer Nachfolgermenge sind genau die kleineren oder gleichen](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L2663): Hinrichtung; Rückrichtung; Zusammenführung.
- [Eindeutiger Vorgaenger einer Nichtnullzahl](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L4379): Existenz; Eindeutigkeit; Eindeutige Existenz.
- [Nachfolgerbijektion auf die Nichtnullzahlen](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L4433): Injektivität auf dem Nichtnullträger; Surjektivität auf dem Nichtnullträger; Bijektivität.
- [Rekursionskern ist kleinster rekursionsadmissibler Graphkandidat](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L5300): Trägerinklusion; Startpaar; Rekursionsabschluss; Minimalität; Zusammenführung.
- [Fixierungslemma für Rekursionskernstufen](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L5783): Fixierung der Nullstufe; Fixierung der Nachfolgerstufe; Zusammenführung.
- [Eindeutige Existenz eines Werts in jeder Stufe](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L6371): Existenz; Eindeutigkeit; Eindeutige Existenz.
- [Existenz einer rekursiv definierten Abbildung](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L6652): Funktionstyp; Anfangswert; Rekursionsgleichung; Zusammenführung und Existenz.
- [Dedekindscher Rekursionssatz](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L6734): Existenz; Eindeutigkeit; Eindeutige Existenz.
- [Surjektivität der Rekursionsabbildung genau beim Induktionsprinzip](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L7323): Hinrichtung; Rückrichtung; Zusammenführung.
- [Folgenverschiebung als Bijektion auf die ausgelassene Zielmenge](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L8730): Injektivität auf der verkleinerten Zielmenge; Surjektivität auf der verkleinerten Zielmenge; Bijektivität.
- [Eindeutiger Vorgänger mit \(+1\)](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L9049): Existenz; Eindeutigkeit; Eindeutige Existenz.
- [Äquivalente Rekursionsschritte](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L9237): Hinrichtung; Rückrichtung; Zusammenführung.
- [Rekursionssatz mit \(n+1\)](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L9282): Existenz; Eindeutigkeit; Eindeutige Existenz.
- [Nachfolgerfall der strikten Ordnung](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L11752): Hinrichtung; Rückrichtung; Zusammenführung.
- [Nachfolger-Anfangsabschnitt: Elementkriterium](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L11951): Hinrichtung; Rückrichtung; Zusammenführung.
- [Ordnung und Anfangsabschnittsinklusion](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L12409): Hinrichtung; Rückrichtung; Zusammenführung.
- [Bijektivität der positiven Fakultätsfunktion](../Bd.%2010%20-%20Natürliche%20Zahlen.tex#L15708): Injektivität; Surjektivität; Bijektivität.

### B11

- [Ununterscheidbarkeitsrelation ist Äquivalenzrelation](../Bd.%2011%20-%20Äquivalenzrelationen.tex#L213): Reflexivität; Symmetrie; Transitivität; Äquivalenzrelation.
- [Gleichmächtigkeit ist eine Äquivalenzrelation](../Bd.%2011%20-%20Äquivalenzrelationen.tex#L388): Reflexivität; Symmetrie; Transitivität; Äquivalenzrelation.
- [Charakterisierung der Quotientenmenge](../Bd.%2011%20-%20Äquivalenzrelationen.tex#L1057): Hinrichtung; Rückrichtung; Zusammenführung.
- [Bijektivität der Ununterscheidbarkeitsquotientenabbildung](../Bd.%2011%20-%20Äquivalenzrelationen.tex#L2403): Injektivität; Surjektivität; Bijektivität.

### B12

- [Eindeutigkeit eines Minimums](../Bd.%2012%20-%20Halbordnungen.tex#L228): Existenz; Eindeutigkeit; Eindeutige Existenz.
- [Ein Minimum ist ein minimales Element](../Bd.%2012%20-%20Halbordnungen.tex#L289): Zugehörigkeit zur Teilmenge; Minimalität; Zusammenführung.
- [Eindeutigkeit eines Maximums](../Bd.%2012%20-%20Halbordnungen.tex#L353): Existenz; Eindeutigkeit; Eindeutige Existenz.
- [Ein Maximum ist ein maximales Element](../Bd.%2012%20-%20Halbordnungen.tex#L413): Zugehörigkeit zur Teilmenge; Maximalität; Zusammenführung.
- [Restriktion einer partiellen Ordnung](../Bd.%2012%20-%20Halbordnungen.tex#L555): Reflexivität; Transitivität; Antisymmetrie; Partielle Ordnung.

### B13

- [Untere Schranken der dualen Ordnung](../Bd.%2013%20-%20Schranken,%20Infima%20und%20Suprema.tex#L868): Erste Inklusion; Zweite Inklusion; Mengengleichheit.
- [Obere Schranken der dualen Ordnung](../Bd.%2013%20-%20Schranken,%20Infima%20und%20Suprema.tex#L944): Erste Inklusion; Zweite Inklusion; Mengengleichheit.

### B14

- [Assoziativität des Paarmengensupremums](../Bd.%2014%20-%20Paarinfima%20und%20Paarsuprema.tex#L432): Träger und Existenz der Suprema; Erste Ungleichung; Zweite Ungleichung; Gleichheit durch Antisymmetrie.
- [Assoziativität des Paarmengeninfimums](../Bd.%2014%20-%20Paarinfima%20und%20Paarsuprema.tex#L629): Träger und Existenz der Infima; Erste Ungleichung; Zweite Ungleichung; Gleichheit durch Antisymmetrie.
- [Inklusionsordnung auf einer Mengenfamilie](../Bd.%2014%20-%20Paarinfima%20und%20Paarsuprema.tex#L816): Reflexivität; Transitivität; Antisymmetrie; Partielle Ordnung.
- [Paarmengeninfimum in einer Mengenfamilie](../Bd.%2014%20-%20Paarinfima%20und%20Paarsuprema.tex#L866): Untere Schranke; Größte untere Schranke; Identifikation des Infimums.
- [Paarmengensupremum in einer Mengenfamilie](../Bd.%2014%20-%20Paarinfima%20und%20Paarsuprema.tex#L930): Obere Schranke; Kleinste obere Schranke; Identifikation des Supremums.

### B15

- [Totale Ordnung der natürlichen Zahlen](../Bd.%2015%20-%20Totale%20Ordnungen.tex#L1157): Reflexivität; Transitivität; Antisymmetrie; Partielle Ordnung; Totalität; Totale Ordnung.

### B16

- [Auswahlrelation ist total](../Bd.%2016%20-%20Wohlordnungen%20und%20Auswahlaxiom.tex#L123): Trägerrelation; Totalität; Zusammenführung.
- [Wohlgeordnete Fasern liefern eine Auswahlmenge](../Bd.%2016%20-%20Wohlordnungen%20und%20Auswahlaxiom.tex#L334): Existenz eines ausgewählten Faserminimums; Eindeutigkeit des ausgewählten Elements; Eindeutige Existenz in jeder Faser.

### B17

- [Multiplikation ganzer Zahlen mit null aus den Axiomen](../Bd.%2017%20-%20Ganze%20Zahlen.tex#L3176): Rechtes Nullgesetz; Linkes Nullgesetz; Zusammenführung.

### B18

- [Die Bruchpaarrelation ist eine Äquivalenzrelation](../Bd.%2018%20-%20Rationale%20Zahlen.tex#L200): Reflexivität; Symmetrie; Transitivität; Äquivalenzrelation.
- [Geschachtelte natürliche und ganzzahlige Kopien in den rationalen Zahlen](../Bd.%2018%20-%20Rationale%20Zahlen.tex#L464): Natürliche Kopie in der ganzzahligen Kopie; Ganzzahlige Kopie im rationalen Träger; Natürliche Kopie im rationalen Träger; Zusammenführung.
- [Null- und Einsklasse](../Bd.%2018%20-%20Rationale%20Zahlen.tex#L601): Nullklasse; Einsklasse; Zusammenführung.
- [Null und Eins sind rationale Zahlen](../Bd.%2018%20-%20Rationale%20Zahlen.tex#L642): Null im rationalen Träger; Eins im rationalen Träger; Zusammenführung.
- [Abgeschlossenheit und doppelte Negation](../Bd.%2018%20-%20Rationale%20Zahlen.tex#L853): Abgeschlossenheit der Negation; Doppelte Negation; Zusammenführung.
- [Quotientenabstieg der rationalen Ordnung](../Bd.%2018%20-%20Rationale%20Zahlen.tex#L2524): Trägerrelation; Auswertung auf Repräsentanten; Zusammenführung.
- [Ordnungsregeln aus Kreuzprodukten](../Bd.%2018%20-%20Rationale%20Zahlen.tex#L2600): Reflexivität; Antisymmetrie; Transitivität; Totalität; Zusammenführung der Ordnungsregeln.
- [Dichte der rationalen Ordnung](../Bd.%2018%20-%20Rationale%20Zahlen.tex#L3519): Rationalität des Zwischenwerts; Untere strikte Schranke; Obere strikte Schranke; Existenz des Zwischenwerts.

### B19

- [Nichtleerheit und Echtheit](../Bd.%2019%20-%20Reelle%20Zahlen.tex#L253): Nichtleerheit; Echtheit; Zusammenführung.
- [Geschachtelter Zahlbereichsturm in den reellen Zahlen](../Bd.%2019%20-%20Reelle%20Zahlen.tex#L796): Einbettungen und Bildinklusionen; Natürliche Kopie in der ganzzahligen Kopie; Ganzzahlige Kopie in der rationalen Kopie; Rationale Kopie im reellen Träger; Übrige Trägerinklusionen; Zusammenführung.
- [Träger, Nichtleerheit und Echtheit](../Bd.%2019%20-%20Reelle%20Zahlen.tex#L968): Nichtleerheit; Trägerinklusion; Echtheit; Zusammenführung.
- [Schrankenmenge ist nichtleer und beschränkt](../Bd.%2019%20-%20Reelle%20Zahlen.tex#L1324): Nichtleerheit der Schrankenmenge; Trägerinklusion; Obere Beschränktheit; Zusammenführung.
- [Involutivität und Null](../Bd.%2019%20-%20Reelle%20Zahlen.tex#L2213): Involutivität; Negation des Nullschnitts; Zusammenführung.
- [Allgemeine Assoziativität, Einheit und Inverses](../Bd.%2019%20-%20Reelle%20Zahlen.tex#L3206): Assoziativität; Kommutativität; Einheit; Multiplikatives Inverses; Zusammenführung.
- [Vorzeichenidentitäten](../Bd.%2019%20-%20Reelle%20Zahlen.tex#L3206): Ein negatives Vorzeichen; Zwei negative Vorzeichen; Multiplikation mit dem Nullschnitt; Zusammenführung.
- [Positive Produktgesetze](../Bd.%2019%20-%20Reelle%20Zahlen.tex#L3206): Assoziativität des positiven Produkts; Kommutativität des positiven Produkts; Einheit des positiven Produkts; Zusammenführung.
- [Nullpunkt einer nichtnegativen Summe](../Bd.%2019%20-%20Reelle%20Zahlen.tex#L3206): Nichtnegativität der Summe; Nullpunktkriterium; Zusammenführung.
- [Erhaltung von Negation und Produkt](../Bd.%2019%20-%20Reelle%20Zahlen.tex#L4388): Erhaltung der Negation; Erhaltung der Multiplikation; Zusammenführung.
- [Negation und Produkt](../Bd.%2019%20-%20Reelle%20Zahlen.tex#L4630): Verträglichkeit mit Negation; Verträglichkeit mit Multiplikation; Zusammenführung.
- [Positivität und Nullkriterium](../Bd.%2019%20-%20Reelle%20Zahlen.tex#L4630): Nichtnegativität; Nullkriterium; Zusammenführung.
- [Positivität, Definitheit und Symmetrie](../Bd.%2019%20-%20Reelle%20Zahlen.tex#L4784): Nichtnegativität; Definitheit; Symmetrie; Zusammenführung.
- [Operationen und Eindeutigkeit](../Bd.%2019%20-%20Reelle%20Zahlen.tex#L6280): Existenz und Operationserhaltung; Eindeutigkeit; Eindeutige Existenz.
- [Suprema und Schnittoperationen](../Bd.%2019%20-%20Reelle%20Zahlen.tex#L6280): Erhaltung der Addition; Erhaltung von Null und Eins; Erhaltung der Negation; Erhaltung der Multiplikation; Zusammenführung.
- [Ordnung und Bijektivität der Supremumsabbildung](../Bd.%2019%20-%20Reelle%20Zahlen.tex#L6280): Ordnungserhaltung und Injektivität; Surjektivität; Ordnungsreflexion; Zusammenführung.

### B20

- [Adjunktion einer Bijektion](../Bd.%2020%20-%20Endliche%20Mengen.tex#L1546): Injektivität; Surjektivität; Bijektivität.
- [Obermengenwahl entpacken](../Bd.%2020%20-%20Endliche%20Mengen.tex#L3165): Funktionstyp; Strikte Erweiterung; Zusammenführung.
- [Totalitaet der Frischelementrelation](../Bd.%2020%20-%20Endliche%20Mengen.tex#L3374): Trägerrelation; Totalität; Zusammenführung.
- [Frischelementauswahl entpacken](../Bd.%2020%20-%20Endliche%20Mengen.tex#L3425): Funktionstyp; Frischelementeigenschaft; Zusammenführung.
- [Endliche Teilmengen bilden eine nichtleere Potenzmengenfamilie](../Bd.%2020%20-%20Endliche%20Mengen.tex#L4163): Potenzmengenfamilie; Nichtleerheit; Zusammenführung.
- [Frische Adjunktion endlicher Teilmengen](../Bd.%2020%20-%20Endliche%20Mengen.tex#L4200): Endlichkeit der Adjunktion; Echte Erweiterung; Zusammenführung.
- [Komplementduale bleibt eine nichtleere Potenzmengenfamilie](../Bd.%2020%20-%20Endliche%20Mengen.tex#L4512): Potenzmengenfamilie; Nichtleerheit; Zusammenführung.
- [Wohldefiniertheit der endlichen Kardinalzahl](../Bd.%2020%20-%20Endliche%20Mengen.tex#L5296): Existenz; Eindeutigkeit; Eindeutige Existenz.
- [Gleichmächtigkeit liefert Vergleiche in beide Richtungen](../Bd.%2020%20-%20Endliche%20Mengen.tex#L6544): Bijektionszeuge und Injektionen; Vergleich in Hinrichtung; Vergleich in Rückrichtung; Zusammenführung.
- [Fixpunktgleichung des Cantor--Bernstein-Teils](../Bd.%2020%20-%20Endliche%20Mengen.tex#L6851): Erste Inklusion; Zweite Inklusion; Fixpunktgleichheit.
- [Cantor--Schröder--Bernstein für feste Injektionen](../Bd.%2020%20-%20Endliche%20Mengen.tex#L7225): Erster bijektiver Zweig; Zweiter bijektiver Zweig; Disjunktheit und Verkleben; Identifikation von Definitions- und Zielbereich.
- [Die Nichtnullzahlen bilden eine echte Teilmenge](../Bd.%2020%20-%20Endliche%20Mengen.tex#L7633): Teilmengeninklusion; Echtheit der Teilmenge; Zusammenführung.

### B21

- [Typisierung, Koordinaten und Bild](../Bd.%2021%20-%20Folgen.tex#L341): Funktionstyp; Koordinaten der Einschränkung; Bildmenge der Einschränkung.
- [Injektivität und Surjektivität](../Bd.%2021%20-%20Folgen.tex#L815): Injektivität; Surjektivität; Bijektivität.
- [Typisierung der rechten Terme](../Bd.%2021%20-%20Folgen.tex#L1268): Negation, Summe und Differenz; Produkt; Betrag; Skalares Vielfaches; Verschiebung um einen konstanten Wert; Funktionstypen der Folgen.
- [Nichtnullbedingung und Typisierung](../Bd.%2021%20-%20Folgen.tex#L1351): Kehrwertfolge; Quotientenfolge; Funktionstypen.
- [Typisierung und Verschiedenheit der Marker](../Bd.%2021%20-%20Folgen.tex#L3481): Trägereigenschaft; Erster und zweiter Marker sind verschieden; Erster und dritter Marker sind verschieden; Zweiter und dritter Marker sind verschieden; Paarweise Verschiedenheit.

## Begründete Beibehaltungen

- Eine einzige Äquivalenzumformung, reine Definitionsextraktion oder die unmittelbare Instanziierung eines bereits separat bewiesenen Satzes wird nicht künstlich in Teilbeweise zerlegt. Eine Konjunktion in einer Definitionsentfaltung allein ist kein Nachweis mehrerer unabhängiger Eigenschaften.
- Eine Fallunterscheidung, die in jedem Fall dasselbe Ziel zeigt, bleibt ein Beweis desselben Ziels; vorhandene Fallgliederung bleibt erhalten. Bereits passend getrennte Induktionsanfänge/-schritte und Implikationsrichtungen bleiben bestehen.
- Sammelsätze, die ausschließlich zuvor separat bewiesene Strukturaxiome zusammenstellen, bleiben Zusammenführungen. Wo innerhalb eines bisherigen Teils mehrere Eigenschaften tatsächlich eigenständig hergeleitet werden (z. B. Schnittträger/Nichtleerheit/Echtheit, Produktgesetze, Abstandsaxiome), wurden zusätzliche Teile eingefügt.

## Nebenbefunde

Korrigiert wurden im Bijektionsband die Schlussvariable beim Bijektivitätsnachweis für `G`, vertauschte Abhängigkeitsangaben in diesem Nachweis, eine falsche Konjunktionselimination und die Annahme-/Ableitungsindizes des eindeutigen Urbilds. Im Naturzahlenband wurden Selbst-/Fehlverweise beim Schnitt induktiver Mengen und mehrere verschobene Indizes im Satz über den kleinsten Rekursionskern korrigiert. Die lokalen `proofstepwidestar`-Redefinitionen in B08 und B21 wurden entfernt, damit die zentrale Spaltenausrichtung greift; B21 behält die ergänzenden Umbruchstellen für Referenzargumente.

Die Entschachtelung echter Theoremargumente (Nutzerpunkt 2) wurde für B02–B16 in einem gesonderten vollständigen Durchgang abgeschlossen; zusätzliche übernommene Nachprüfungen betreffen B18 und B21.


## Zweiter Prüfschritt: eigenständige Theoremprämissen B02–B16

In der anschließenden vollständigen Prämisseninventur wurden 477 konkrete Theoremaufrufe in eigene nummerierte Beweiszeilen angehoben. Hinzu kommen sieben explizit ausgeführte frühe Mengenbeweise (Schnitt, Schnittidempotenz und Einermengencharakterisierung); die Nettoänderung beträgt 495 zusätzliche Tabellenzeilen. Fortsetzungszähler, Argumentindizes und Abhängigkeiten wurden angepasst. Wenn eine eingefügte Hilfsaussage eine Gleichungskette unterbricht, steht deren nächster linker Ausdruck ausdrücklich in der Tabelle. Die Schlussinventur schließt auch neun ältere, manuell mit runden Klammern gesetzte Anwendungen in B10 ein: deren 22 Prämissen stehen nun einzeln, ebenso die beiden Vorgängertypen eines zuvor mit `rAIRepeat` zusammengefassten Arguments.

| Band | Angehobene Theoremaufrufe |
|---|---:|
| B02 | 0 |
| B03 | 63 |
| B04 | 2 |
| B05 | 24 |
| B06 | 6 |
| B07 | 10 |
| B08 | 91 |
| B09 | 0 |
| B10 | 128 |
| B11 | 13 |
| B12 | 8 |
| B13 | 2 |
| B14 | 10 |
| B15 | 14 |
| B16 | 6 |

Die erste Anwendung wurde an einem unabhängigen Beispiel mit verschachtelten Kind-/Elternprämissen, kollidierenden alten/neuen Nummern und fortgesetzter Nummerierung geprüft. Der anschließende Strukturvergleich bestätigt unveränderte Satz-/Definitions-/Axiomformulierungen und registrierte Proofpart-Formeln in B02–B16. Sämtliche erfassten Beweis- und Referenzmakros lassen sich weiterhin vollständig lesen; keine temporären Indexplatzhalter verblieben. `git diff --check` ist ohne Befund. Diese Kontrollen sind Struktur- und Redaktionsprüfungen, kein maschineller Nachweis der vollständigen mathematischen Gültigkeit.

Begründete Ausnahmen: B02 verwendet reine logische Äquivalenzschemata in Ersetzungsregeln. In B03 bleiben Schemata für Negation und elementare Mengenumformungen bestehen. B12 enthält eine parallele Quellenliste für drei Trägerzugehörigkeiten; B16 verwendet definitorische Äquivalenzwrapper für ACsur, WOP und WellOrdable. Sie sind keine eingesetzten bewiesenen Einzelaussagen mit verborgenen Argumentzeilen. Eine erneute Strukturinventur findet innerhalb eines anderen Theoremaufrufs nur noch zwei solcher B03-Schemaverweise (Extensionalität beziehungsweise Mengenbildung unter logischer Negation); alle übrigen B02–B16-Bände haben dort null Vorkommen.

Zusätzlich korrigiert wurden fehlende Abhängigkeiten und Rückverweise in frühen Teilmengen-/Schnittbeweisen, der falsche Einermengen-Rückverweis beim zweiten Element, eine fehlende Mengenklammer in der Paarrekonstruktion und die Potenzmengen-Zugehörigkeit des leeren Arguments einer Umkehrabbildung.

Die abschließende Indexprüfung zeigte ferner einen Selbstverweis im Differenz-Teilmengenbeweis B03 sowie mehrere ältere Verschiebungen in der Transitivitätsinduktion B10. Beide Beweise wurden einschließlich Annahmenabhängigkeiten und Entlassungen korrigiert.

## Ergänzender Prämissendurchgang B18 und B21

B18 wurde nach dem ersten zentralen Prämissendurchgang erneut vollständig erfasst. 96 weitere konkrete Theoremaufrufe stehen separat; zusammen mit überarbeiteten Beweisen steigt dieser Arbeitsstand von 808 auf 954 Tabellenzeilen. Bei der Äquivalenzrelation auf rationalen Paaren sind Vertreterwahl, Trägerzugehörigkeit und die drei Relationseigenschaften ausdrücklich nachgewiesen. Der Klassenvergleich benutzt getrennte Klassenidentitäten. Beim Archimedizitätsbeweis werden die Abbildungstypen von den Typen ihrer Werte unterschieden; die positive Multiplikation und die nötigen Kommutativitätsumformungen stehen explizit da. Nullkriterium, Kehrwertvorzeichen und die linksseitige Übersetzung einer rechtsseitig formulierten Ordnungsaxiomatik wurden korrigiert. Die letzte Inventur findet keine Theoremreferenz als verborgenes Argument eines anderen Theoremaufrufs mehr.

In B21 wurden im übernommenen Nachdurchgang 94 weitere Prämissen angehoben, einschließlich sieben bei der letzten Gesamtinventur im vorderen Bandteil entdeckter Fälle. Die Folgentypen punktweiser Operationen und die Typen benutzter Folgenglieder stehen getrennt. Für die Marker der Mogiljanskaja-Konstruktion werden dargestellte Elemente, benötigte natürliche Indizes und die Gleichheit der beiden Koordinaten separat ausgewiesen. Ein überflüssiger Nachfolgerverweis bei `DeltaBijective` wurde entfernt; bei der verschobenen Parametrisierung sind beide benötigten Nachfolgerstufen ausdrücklich typisiert.

Vier Schrankenbeweisteile in B21 wurden zusätzlich überarbeitet: der leere Anfangsabschnitt, die Zusammenführung von Anfangs- und Restschranke sowie die Restschranken konvergenter und Cauchy-Folgen. Die Beweise enthalten nun die tatsächlichen Träger- und Nichtnegativitätsargumente für `C+D`, `1+|L|` und `1+|a_N|`. Dabei wird die Translationsmonotonie mit der additiven Einheit und der Transitivität der Schnittinklusion verbunden. Im Induktionsanfang wird `0≤0` ausdrücklich bewiesen; eine Aussage über die totale Ordnung steht nicht mehr an seiner Stelle.

Die ergänzende Schlusskontrolle vergleicht die Satz-, Definitions-, Axiom- und registrierten Proofpart-Formulierungen mit dem jeweiligen Arbeitsbeginn, prüft die Makrostruktur und sucht Selbst- beziehungsweise Vorwärtsverweise in wörtlichen Theoremargumentlisten. Sie ersetzt keine formale Beweisprüfung. Parallele Quellenangaben für kurze algebraische Umformungen und reine Definitionsschemata bleiben begründet erhalten.
