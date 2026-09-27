# Nächste Lesefassung: Themenwahl und Aufbau

Stand: 20. September 2026. Grundlage ist der aktuelle Arbeitsstand der LaTeX-Quellen einschließlich der noch nicht eingecheckten Änderungen.

**Nachtrag vom 21. September 2026:** Die empfohlene Lesefassung und der
separate Beweisband sind inzwischen umgesetzt. Die endgültige Entscheidung
des Autors sieht einen Hauptsatz in Band 28 und sechs Hilfsresultate im
Beweisband vor: Die Klammerungsunabhängigkeit bleibt als Satz 28.2.3.4 im
Haupt- und Gesamtband, zusammen mit der Anmerkung zur Produktschreibweise.
Der Beweisband enthält die übrigen sechs Aussagen und alle sieben
Tabellenbeweise; beim Schlussbeweis verweist er nur auf den Hauptsatz.
Diese Aufteilung ersetzt sowohl den unten festgehaltenen historischen
Plan mit drei Hauptbandaussagen als auch den zwischenzeitlichen Stand
mit allen sieben Aussagen im Beweisband. Den aktuellen Inhalt und Prüfstand dokumentiert der
[Umsetzungsbericht](klammerungsunabhaengigkeit-auslagerung-2026-09-20.md).
Der folgende Text hält die zugrunde liegende Themenwahl und Konzeption fest.

## Empfehlung

**„Warum wir Klammern weglassen dürfen – von drei Faktoren zu beliebig langen Produkten“**

Die nächste Lesefassung sollte die **Klammerungsunabhängigkeit in Halbgruppen** behandeln. Ihre Grundlagen stammen aus Band 27, der Hauptsatz und seine unmittelbar tragenden Beweise aus dem Anfang von Band 28.

Die Leitfrage ist einfach zu stellen: Das Assoziativgesetz betrifft drei Elemente. Warum genügt es, damit jede binäre Klammerung einer beliebig langen, aber festen Faktorenfolge denselben Wert ergibt?

Das Thema eignet sich besonders, weil es eine vertraute Schreibgewohnheit begründet, einen abgeschlossenen Beweis besitzt und mehrere Grundlagen des Manuskripts zusammenführt. Wörter, Bäume, Rekursion und Induktion bekommen dabei jeweils eine erkennbare Aufgabe. Gegenüber Cantor–Bernstein und Dedekind kommt eine andere Leitidee hinzu: Man führt verschiedene Ausdrücke auf denselben Vergleichswert zurück.

Die Empfehlung umfasst nach der Ergänzung vom 20. September ausdrücklich ein Paar aus Lesefassung und eigenständigem Beweisband. Die folgende Aufteilung beschreibt das anschließend umgesetzte Konzept.

## Was die bestehenden Lesefassungen leisten

Gelesen wurden die aktuellen Lesetexte zu Cantor–Schröder–Bernstein, zum Dedekindschen Rekursionssatz und zum Mogiljanskaja-Gegenbeispiel. Zentrale Beweisschritte wurden nachvollzogen. In diesen geprüften Schritten wurde kein mathematischer Fehler gefunden. Dies ist keine vollständige Prüfung sämtlicher Tabellen, historischer Quellen oder aller 48 Fachbände; PDF-Layout und Links waren nicht Gegenstand dieser Prüfung.

### Cantor–Schröder–Bernstein

**Aufbau:** Aussage und Zerlegungsziel; kleinste abgeschlossene Teilmenge; Fixpunktgleichung; Bild des zweiten Zweiges; Zusammensetzen der Bijektion; Anschluss an Gleichmächtigkeit; Vergleich verschiedener Beweiswege.

**Was gut funktioniert:** Die Motivation sagt früh, welche Gleichung die beiden Zweige miteinander verbinden muss. Die Hilfsmenge erscheint dadurch als Lösung eines konkreten Problems. Im Beweis werden Minimalität, Komplementbildung und die Verwendung der Injektivität ausdrücklich begründet. Auch die Injektivität zwischen den beiden Zweigen wird behandelt.

**Gezielte Ergänzung:** Vor der Definition des Startbereichs noch deutlicher sagen: Auf Punkten aus \(A\setminus G[B]\) kann man nicht rückwärts entlang von \(G\) gehen. Dort muss der \(F\)-Zweig beginnen. Wird \(a\) über \(F\) zugeordnet, ist \(F(a)\) bereits belegt; deshalb muss auch \(G(F(a))\) in den \(F\)-Zweig wechseln. Damit wird die Abschlussbedingung bereits aus der Aufgabe heraus verständlich.

**Fundstellen:** [Motivation](../tex/b08/cantor-bernstein/motivation.tex), besonders Zeilen 24–40; [Lesebeweis](../tex/b08/cantor-bernstein/lesebeweis.tex), Zeilen 24–62, 92–106 und 144–150.

### Dedekindscher Rekursionssatz

**Aufbau:** Zweizustandsbeispiel; Frage nach einer Funktion auf allen natürlichen Zahlen; Aussage und Voraussetzungen; Rekursionskern; eindeutiger Wert pro Stufe; Graph als Funktion; Eindeutigkeit der Lösung; Einordnung und Vergleich mit Dedekinds Vorgehen.

**Was gut funktioniert:** Das Beispiel wird im Beweis wieder aufgegriffen. Es erklärt den Unterschied zwischen verschiedenen Stellen und möglicherweise gleichen Werten sowie das Problem zunächst mehrwertiger Relationen. Besonders gelungen ist die Trennung zwischen eindeutigen Werten innerhalb des Graphen und der Eindeutigkeit der gesamten Lösung. Auch Induktion und Rekursion werden auseinandergehalten.

Die Fixierungsmenge im Nachfolgerschritt verwendet nur die bereits bekannte Eindeutigkeit der vorherigen Stufe. Die Funktionseigenschaft wird dadurch nicht vorausgesetzt, sondern begründet.

**Gezielte Ergänzung:** Die Anwendung am Ende einmal konkret durchführen: Für festes \(a\in\mathbb N\) setze \(M=\mathbb N\), \(m_0=a\) und \(f=\operatorname{Succ}\). Der Satz liefert eindeutig \(F_a(0)=a\) und \(F_a(n+1)=\operatorname{Succ}(F_a(n))\). Daran wird sichtbar, wie Rekursion die spätere Definition der Addition ermöglicht.

**Fundstellen:** [Lesetext](../tex/b10/dedekind/reading.tex), Zeilen 4–29, 110–117, 174–274 und 328–366. Diese Fassung ist das beste allgemeine Vorbild für den Aufbau der nächsten Lesefassung.

### Mogiljanskaja-Gegenbeispiel

**Aufbau:** Rekonstruktionsfrage; zwei Grundhalbgruppen und ihre Nichtisomorphie; genaue Produktformel; Reservefamilie ohne Produktrechtecke; zwei Verschiebungen; Bijektion der nichtleeren Potenzmengen; Homomorphiebeweis; Bedeutung und Vergleich mit der Originalarbeit.

**Was gut funktioniert:** Die Fassung zeigt, warum eine besondere Bijektion erforderlich ist. Bloße Gleichmächtigkeit der Potenzmengen würde nicht ausreichen. Die Reserve darf gerade diejenigen Mengen bewegen, welche die Multiplikation nicht als Rechtecke erzeugt. Besonders aufschlussreich ist das Schlussbeispiel, in dem eine dreielementige Menge auf die neue Einermenge \(\{k\}\) abgebildet wird.

Der Homomorphiebeweis trennt zwei notwendige Schritte: Das Produkt der Bilder stimmt mit dem ursprünglichen Produkt überein, und die Abbildung lässt dieses Produkt selbst fest. Erst gemeinsam ergeben diese Aussagen die Homomorphiegleichung.

**Gezielte Ergänzung:** Vor der Reservekonstruktion die Anforderungen noch einmal knapp bündeln: Produktrechtecke und leere Menge festhalten; nur den betreffenden Mengenanteil umordnen; alle neuen \(k\)-haltigen Mengen genau einmal erreichen. So behalten die Leser bei den vielen Mengen und Familien das Ziel im Blick.

**Fundstellen:** [Lesetext](../tex/b28/mogiljanskaja/reading.tex), Zeilen 206–223, 263–277, 312–367, 445–552 und 568–592.

### Gemeinsame Folgerung

Die Stärke der Reihe ist die Verbindung aus verständlicher Fragestellung und ausführlich begründetem Beweis. Entscheidende Übergänge sollten auch künftig ausgeschrieben werden. Die dokumentierten Anmerkungsrunden zu Cantor–Bernstein und Mogiljanskaja bestätigen, dass diese Ausführlichkeit bewusst gewünscht ist.

Für die neue Fassung würde ich deshalb übernehmen: ein wiederkehrendes Beispiel; eine präzise Aussage; vorab erklärte Aufgaben der Hilfsbegriffe; einen vollständigen Prosabeweis des Hauptarguments; eine anschließende Anwendung. Ein historischer Vergleich ist sinnvoll, wenn er einen zusätzlichen Beweisgedanken erklärt und anhand der Originalquelle geprüft wird. Er muss nicht in jeder Lesefassung ein gleich langer Pflichtteil sein.

## Konkreter Aufbau der empfohlenen Lesefassung

### 1. Drei Faktoren sind erst der Anfang

Mit \((a\star b)\star c=a\star(b\star c)\) beginnen. Anschließend die fünf Klammerungen von vier Faktoren nebeneinander zeigen. Die Frage lautet: Warum funktioniert das für jede endliche Länge, ohne alle Klammerungen einzeln durchzurechnen?

Den Zielsatz bereits hier in Worten nennen: **In einer Halbgruppe haben alle vollständigen binären Klammerungen derselben nichtleeren Faktorenfolge denselben Wert.**

Als Gegenbeispiel für eine beliebige binäre Operation dient die Subtraktion auf den ganzen Zahlen: \((8-3)-2=3\), aber \(8-(3-2)=7\).

### 2. Faktorenfolge, Klammerung und Wert

Drei Ebenen unterscheiden:

- Das **Wort** speichert die Faktoren in ihrer Reihenfolge, einschließlich Wiederholungen.
- Der **Baum** speichert, welche Teilprodukte zuerst gebildet werden.
- Die **Auswertung** ordnet dem Baum ein Element des Trägers zu.

Das vorhandene Beispiel `aba` ist nützlich: Die Menge \(\{a,b\}\) verliert Reihenfolge und Wiederholung. Gleiche Blattbeschriftungen bedeuten außerdem nicht, dass es sich um denselben Blattknoten handelt.

### 3. Klammerungen als Bäume lesen

Ein Blatt trägt einen Faktor. Ein innerer Knoten verbindet einen linken und einen rechten Teilbaum. Das Blattwort liest die Faktoren von links nach rechts; die Auswertung multipliziert die Werte der Teilbäume.

Ein Beispiel mit vier Faktoren wird als Klammerausdruck und Baum gezeigt und von unten nach oben ausgewertet. Die strukturelle Induktion wird an diesen zwei Fällen erklärt: Aussage für Blätter; Erhaltung beim Verbinden zweier Bäume.

Wort- und Baumrekursion sowie die Induktionsprinzipien werden als in Band 27 begründete Werkzeuge mit ihren genauen Regeln angegeben. Die vollständige mengen-theoretische Konstruktion dieser Werkzeuge bleibt dort nachlesbar.

### 4. Ein fester Vergleichswert: das Linksprodukt

Zunächst eine einzige Auswertungsweise festlegen:

\[
P(a)=a,\qquad P(wa)=P(w)\star a.
\]

Beispiel: \(P(abcd)=((a\star b)\star c)\star d\). Dafür genügt eine binäre Operation; Assoziativität wird noch nicht benötigt. So entsteht kein Zirkelschluss durch die Verwendung eines bereits ungeklammerten Produkts.

### 5. Der entscheidende Schritt: zwei Blöcke zusammenfassen

Für nichtleere Wörter \(u,v\) den Satz

\[
P(uv)=P(u)\star P(v)
\]

vollständig beweisen. Für festes \(u\) erfolgt Induktion über \(v\). Der Anfang ist ein einzelner Buchstabe. Der Übergang vom Wort \(v\) zum Wort \(va\) lautet:

\[
\begin{aligned}
P(u(va))&=P((uv)a)\\
&=P(uv)\star a\\
&=(P(u)\star P(v))\star a\\
&=P(u)\star(P(v)\star a)\\
&=P(u)\star P(va).
\end{aligned}
\]

Jede Gleichheit erhält ihre Begründung: Wortverkettung; Definition des Linksprodukts; Induktionsannahme; Assoziativität auf dem Träger; erneut Definition des Linksprodukts. Gerade die Unterscheidung zwischen dem Verketten von Wörtern und dem Multiplizieren ihrer Werte ist didaktisch entscheidend.

### 6. Jeder Baum hat denselben Vergleichswert

Durch strukturelle Induktion zeigen:

\[
\operatorname{ev}(T)=P(\operatorname{wort}(T)).
\]

Der Blattfall ist unmittelbar. Beim Knoten werden die beiden Induktionsannahmen eingesetzt; das Blockgesetz verbindet anschließend die beiden Blattwörter. Damit ist der eigentliche Hauptsatz kurz: Haben zwei Bäume dasselbe Blattwort \(w\), so haben beide den Wert \(P(w)\).

Das Beispiel vom Anfang wird jetzt auf den allgemeinen Satz zurückgeführt. Eine Zeichnung mit zwei unterschiedlichen Bäumen, demselben Blattwort und demselben Produktwert macht die drei Ebenen erneut sichtbar.

### 7. Was wir jetzt schreiben dürfen

Nun ist die klammerfreie Schreibweise \(a_1\star\cdots\star a_n\) für \(n\geq1\) gerechtfertigt. Faktoren dürfen dabei nicht ohne weitere Voraussetzung vertauscht werden. Kommutativität war keine Beweisvoraussetzung; ein neutrales Element ebenfalls nicht.

Als Anwendung eignet sich die Komposition mehrerer Funktionen: Unterschiedliche Klammerungen ändern den Wert nicht, die Reihenfolge kann ihn sehr wohl ändern. Das Leerprodukt wird nur als Anschluss an Monoide erwähnt, wo ein neutrales Element zur Verfügung steht.

Optional kann ein kurzer Rückblick ergänzen: Gilt Klammerungsunabhängigkeit für alle endlichen nichtleeren Faktorenfolgen, dann insbesondere für drei Faktoren, also gilt Assoziativität. Diese umgekehrte Richtung wäre eine kurze ausdrücklich ergänzte Beobachtung.

## Anbindung an die vorhandenen Beweise

| Rolle in der Lesefassung | Vorhandene Quelle |
| --- | --- |
| Wörter und wiederholte Buchstaben | Band 27, Zeile 111 |
| Zwei Bäume mit gleichem Blattwort | `tex/b27-tree-example.tex`, ab Zeile 1 |
| Linksprodukt für eine beliebige binäre Operation | Band 27, ab Zeile 1816 |
| Linksbaum und Zusammenhang mit der Linksfaltung | `tex/b27-left-bracketing.tex`, Zeile 343; `tex/b27-left-bracketing-evaluation.tex`, Zeile 52 |
| Blockgesetz | Band 28, Zeile 274, ID `SemigroupWordBlockLaw`; Induktionsschritt ab Zeile 185 |
| Baum-Normalform | Band 28, Zeile 433, ID `SemigroupTreeNormalForm`; Knotenfall ab Zeile 340 |
| Klammerungsunabhängigkeit | Band 28, Zeile 457, ID `SemigroupBracketingIndependence` |

Die untersuchte Beweiskette benötigt keine neue mathematische Hauptkonstruktion. Wortverkettung und Linksfaltung werden vor dem Halbgruppenargument begründet; die Assoziativität der Werteoperation kommt ausdrücklich im Blockgesetz hinzu. Die Lesefassung muss daher nicht den gesamten Band 27 nacherzählen. Baumcodierungen, Positionsgraphen und kanonische Strukturisomorphismen gehören nicht in ihren Hauptgang.

Die allgemeinen Grundlagen bleiben an ihrem Ort. Die folgende Ergänzung legt fest, welche Beweisblöcke einen eigenen Begleitband erhalten und wie dieser mit Lesefassung und Hauptband verbunden wird.

## Ergänzung: Lesefassung und Beweisband als zusammengehöriges Paar

### Zwei Ausgaben neben dem Hauptband

Geplant sind zwei PDFs im selben Ergänzungsordner:

- **Bd. 28 – Klammerungsunabhängigkeit – Lesefassung:** der oben beschriebene Text mit Beispielen, Diagrammen und vollständigem Prosabeweis.
- **Bd. 28 – Klammerungsunabhängigkeit – Beweistabellen:** die präzisen Aussagen mit Voraussetzungen, die vier lokalen Hilfssätze und sämtliche sieben zugehörigen Beweisblöcke.

Der vorgeschlagene Ablageort ist `output/07 Halbgruppen und Monoide/Ergänzungen/Klammerungsunabhängigkeit/`. Beide Ausgaben gehören als Ergänzungen zu Band 28; es wird keine neue Nummer in der Reihe der 48 Fachbände benötigt. Auf dem Titelblatt und im Einstieg wird die Grundlage aus Band 27 genannt.

Die Lesefassung begründet die entscheidenden Übergänge selbst. Der Beweisband enthält zu jeder Tabelle ihre Aussage und Voraussetzungen und bleibt dadurch mit den angegebenen Grundlagen auch ohne paralleles Lesen der Lesefassung verständlich.

### Welche Blöcke ausgelagert werden

Der Kern umfasst die folgenden sieben vorhandenen Beweisblöcke aus Band 28, derzeit zwischen den Abschnitten „Produkte endlicher Wörter“ und „Klammerungsunabhängigkeit“:

| Aussage | Kennung | Künftige Rolle |
| --- | --- | --- |
| Anfangsfall des Blockgesetzes | `SemigroupWordBlockBase` | Lokaler Hilfssatz im Beweisband |
| Induktionsschritt des Blockgesetzes | `SemigroupWordBlockStep` | Lokaler Hilfssatz im Beweisband |
| Blockgesetz | `SemigroupWordBlockLaw` | Aussage im Hauptband, vollständige Tabelle im Beweisband |
| Blattfall der Baum-Normalform | `SemigroupTreeNormalFormLeaf` | Lokaler Hilfssatz im Beweisband |
| Knotenfall der Baum-Normalform | `SemigroupTreeNormalFormNode` | Lokaler Hilfssatz im Beweisband |
| Baum-Normalform | `SemigroupTreeNormalForm` | Aussage im Hauptband, vollständige Tabelle im Beweisband |
| Klammerungsunabhängigkeit | `SemigroupBracketingIndependence` | Aussage im Hauptband, vollständige Tabelle im Beweisband |

Die aktive Quelltextsuche findet außerhalb dieser Kette nur Verweise aus der Übersicht zu Band 28 auf das Blockgesetz und die Klammerungsunabhängigkeit. Die vier Fall- und Induktionshilfssätze haben nach dieser Suche keine Verwendung außerhalb der Kette. Ergänzend sind bei der Umsetzung die registrierten Formelverweise und PDF-Ziele zu prüfen, da eine Suche nach benannten Kennungen allein keine vollständige Verwendungsprüfung ersetzt.

### Aufbau des Beweisbands

1. **Voraussetzungen und Notation.** Halbgruppe, nichtleere Wörter, Verkettung, Linksprodukt, Klammerungsbaum, Blattwort und Auswertung. Die benötigten Rekursionsgleichungen und Induktionsprinzipien werden mit Verweisen auf Band 27 zusammengestellt.
2. **Blockgesetz.** Anfangsfall, Induktionsschritt und abschließende Wortinduktion; jeweils Aussage, Kontext und vollständige Beweistabelle.
3. **Baum-Normalform.** Blattfall, Knotenfall und abschließende strukturelle Induktion; die Anwendung des Blockgesetzes bleibt sichtbar.
4. **Klammerungsunabhängigkeit.** Hauptsatz und Schlussbeweis über das gemeinsame Blattwort.

Vor jedem größeren Block erläutert ein kurzer Absatz seine Aufgabe. Die Gliederung entspricht den tragenden Schritten der Lesefassung, sodass man zwischen beiden Darstellungen wechseln kann.

### Was in den Fachbänden bleibt

**Band 27** behält die allgemeinen Definitionen, Konstruktionen und Beweise über Wörter, Bäume, Rekursion, Induktion, Blattwörter und Auswertungen. Der Beweisband nennt die konkret benötigten Ergebnisse mit ihren Voraussetzungen; er übernimmt nicht die gesamte Grundlagentheorie. In der Übersicht zu Band 27 wird auf die neue Anwendung verwiesen.

**Band 28** behält die Halbgruppendefinition, eine kurze Erklärung endlicher Produkte sowie die Aussagen von Blockgesetz, Baum-Normalform und Klammerungsunabhängigkeit. Bei diesen Aussagen führen Links zum Prosabeweis und zum zugehörigen Tabellenabschnitt. Die vier nur innerhalb des Beweises benötigten Hilfssätze und alle sieben Tabellen stehen künftig im Beweisband.

**Der Gesamtband** folgt derselben Aufteilung wie der Hauptband. Er enthält die drei zentralen Aussagen und die Verweise auf die Ergänzungen. Band 00 und das PDF-Verzeichnis erschließen beide neuen Ausgaben.

### Quellen, Nummern und Navigation

Die mathematischen Aussagen werden jeweils aus einer gemeinsamen Quelle eingebunden. Die Tabellen werden verschoben und weiterhin an genau einer Stelle gepflegt. Lesetext und formale Ableitung bleiben zwei eigenständige, aufeinander abgestimmte Darstellungen.

Die bestehenden semantischen Kennungen bleiben erhalten. Die Drucknummern der drei im Hauptband verbleibenden Sätze werden gezielt stabil gehalten; das Entfernen der vier Hilfsaussagen darf nicht unbemerkt nachfolgende Nummern verschieben. Die verlagerten Hilfssätze erhalten ihre eindeutigen Referenzziele im Beweisband. Getrennte Register und gefilterte Importe verhindern konkurrierende Einträge oder eine Kollision mit der schon vorhandenen Mogiljanskaja-Ergänzung.

Die Lesefassung verlinkt an ihren drei tragenden Schritten die entsprechenden Beweisabschnitte. Der Beweisband erhält Rückverweise zu diesen Erklärungen. Vom Hauptband aus sind beide Darstellungen erreichbar. Die technischen Dateinamen und Registerpfade werden an das bestehende Ergänzungssystem angepasst.

### Umsetzung und Abschlussprüfung

Zuerst werden die sieben Blöcke und ihre Referenzen abgegrenzt und die gemeinsamen Quellen angelegt. Anschließend entstehen der Beweisband und der dazu passende Lesetext. Danach werden Hauptband, Gesamtband, Übersichten, Build-Skripte und Veröffentlichungsverzeichnis auf die neue Aufteilung umgestellt.

Vor der Veröffentlichung werden die Voraussetzungen und tragenden Schritte beider Darstellungen miteinander abgeglichen. Die sieben Tabellen müssen vollständig erhalten sein. Beide neuen PDFs und die betroffenen Hauptausgaben werden gebaut; Nummern, Register und eingehende sowie ausgehende Links werden geprüft. Die neuen PDFs werden vollständig gerendert und visuell kontrolliert. Die technischen Prüfungen ersetzen keine mathematische Prüfung der Beweise.

**Umsetzungsstand:** Die neuen LaTeX-Ergänzungen, die Auslagerung aus Band 28,
die Verweisanbindung und beide PDFs sind erstellt. Maßgeblich für den
Prüfstand ist der oben verlinkte Umsetzungsbericht.

## Weitere geeignete Themen

| Thema | Möglicher Aufbau | Bewertung |
| --- | --- | --- |
| **Ein kleines Mengenglied erzwingt ein häufiges Element** — Band 46 | Endliche vereinigungsabgeschlossene Familien und Häufigkeit; Einermengenfall; Zerlegung nach zwei Elementen in vier Klassen; Injektion zwischen den äußeren Klassen; Vergleich der gemischten Klassen; Schluss für eine enthaltene Zweiermenge. | Starke zweite Wahl: anschaulich, überraschend und klar begrenzt. Die allgemeine Frankl-Vermutung dient als Motivation; bewiesen werden die genannten Spezialfälle. |
| **Wie aus rationalen Zahlen eine vollständige Ordnung entsteht** — Band 19 | Dedekindsche Schnitte; Einbettung der rationalen Zahlen; Ordnung durch Inklusion; Vereinigung einer nichtleeren nach oben beschränkten Schnittfamilie; Nachweis, dass diese Vereinigung ihr Supremum ist. | Besonders geeignet für eine zugängliche Lesefassung zum Aufbau der Analysis. Schnittarithmetik und die gesamte Körperkonstruktion sollten außerhalb des Hauptgangs bleiben. |
| **Warum Gruppen aus ihren Potenzhalbgruppen rekonstruierbar sind** — Band 40 mit Grundlage aus Band 38 | Rekonstruktionsfrage wieder aufnehmen; Einheiten erklären; Einheiten der Gruppenpotenzhalbgruppe als genau die Einermengen erkennen; Erhaltung durch Isomorphismen; Gruppenisomorphismus zurückgewinnen. | Beste unmittelbare Fortsetzung zum Mogiljanskaja-Text. Für eine kompakte Fassung zunächst zwei Gruppen voraussetzen. Die stärkere einseitige Gruppenstarrheit benötigt einen deutlich längeren Beweis. |
| **Wann fehlen Grenzwerte?** — Band 47 | Konvergenz und Cauchy-Eigenschaft; Folge \(1/(n+1)\) in der punktierten reellen Geraden; fehlender Grenzwert im Teilraum; vollständige Räume; abgeschlossene Teilräume vollständiger Räume. | Gut zugänglich und in sich geschlossen. Der Band enthält schon viele Prosabeweise; der zusätzliche Gewinn liegt vor allem in Beispielen und einer gezielten Leserführung. |

Die unmittelbaren Belegstellen sind Band 46, Zeilen 509–534 und 1046–1119; Band 19, Zeilen 982–1290; Band 38, ab Zeile 1001, sowie Band 40, Zeilen 951–1124; Band 47, Zeilen 772–842.

Zwei Themen würde ich derzeit als nächste geschlossene Beweisstudie zurückstellen:

- **Auswahlaxiom und Wohlordnungssatz:** Band 16 hält ab Zeile 272 ausdrücklich fest, dass das benötigte Zermelosche Konstruktionsprinzip noch als Axiom eingesetzt wird. Eine Darstellung der vollständigen Äquivalenz müsste diese Grundlage zusätzlich ausarbeiten oder den bedingten Beweisstand offen angeben.
- **Kontinuumshypothese und Unabhängigkeit:** Die aktuelle Beweisbilanz in `tex/b48/06-beweisbilanz.tex`, Zeilen 5–21, kennzeichnet offene Voraussetzungen der weiterführenden Beweiskette. Für eine eigenständige vollständige Beweislesefassung wäre zunächst zusätzliche Grundlagenarbeit erforderlich.

Für die nächste Veröffentlichung bleibt die Klammerungsunabhängigkeit die ausgewogenste Wahl: ein leicht formulierbares Problem, eine vorhandene Beweiskette, passende Bilder und ein neuer mathematischer Gedanke innerhalb der bisherigen Reihe.
