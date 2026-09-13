# Nachprüfung der Bände 1 bis 27

Stand: 13. September 2026, nach dem ersten Umbau. **Prüfbericht mit konkreten
Änderungsvorschlägen; die zusätzlichen Befunde dieses Berichts sind noch nicht
in den Manuskriptquellen umgesetzt.**

## Ergebnis

Die erste Umstellung betraf bereits deutlich mehr als Band 3 und Band 27:
Bis einschließlich Band 27 stehen **165 Anwendungen der Teilmengenregel in
14 Bänden**. Das sind die Bände **3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 19, 20,
26 und 27**. Außerdem wurden bei den Verlagerungen allgemeine Sätze in
Band 2 und Band 21 aufgenommen, obwohl diese beiden Bände keine direkte
Anwendung der neuen Teilmengenregel enthalten. Die bisher genannten
217 Anwendungen in 20 Bänden schließen auch spätere Bände ein.

Die erneute Prüfung findet dennoch **weitere echte Kürzungen und formale
Lücken**. Die erste Umstellung war insofern nicht vollständig. Eine erfolgreiche
LaTeX- und Linkprüfung kann fehlende Annahmenentladungen oder einen unzulässigen
Übergang vom Elementlemma zur Inklusion nicht erkennen.

Konkret sind **27 weitere Kürzungen in zehn Bänden** ausgearbeitet, die
zusammen **95 Zeilen** einsparen könnten. Das ist die Einsparung der
Kürzungsvorschläge, keine Gesamt-Nettozahl: Die ebenfalls nötigen Reparaturen
und eine neue allgemeine Aussage in Band 21 sind gesondert zu berücksichtigen.

## Prüfung aller Bände

Gezählt werden bestehende direkte Regelanwendungen, nicht die Zahl der
Theoreme oder der PDFs mit geänderten Verweisen. Die Quelldateien wurden
einschließlich ihrer aktiven Einbindungen untersucht. Historische
`iffalse`-Blöcke und Kommentare wurden aus der zentralen Inventur entfernt;
bei zweispaltigen Beweisformeln wurden beide Formelseiten berücksichtigt.
Die Inventur erfasst **1.790 Tabellenzeilen mit Teil-/Obermengennotation**;
darunter sind auch Annahmen, echte Inklusionen und zusammengesetzte Aussagen.
Die jeweiligen Schlussbegründungen und relevante Element-/Quantorblöcke
wurden gesondert geprüft. Band 0 ist eine Übersicht ohne eigene Beweistabellen.

| Band | Bestehende Regelanwendungen | Ergebnis der Nachprüfung |
|---|---:|---|
| [1: Grundlagen der Logik](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 01 - Grundlagen der Logik.pdf>) | 0 | Die Teilmengensprache ist hier noch nicht eingeführt. |
| [2: Theoreme der Logik](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 02 - Theoreme der Logik.pdf>) | 0 | Allgemeine Eindeutigkeitslogik aus Band 27 bereits aufgenommen; Teilmengenregel erst ab Band 3. |
| [3: Mengenlehre](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 03 - Mengenlehre.pdf>) | 54 | Weitere Kürzungen und Korrekturen gefunden; siehe Prüfdetails. |
| [4: Totale Relationen](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 04 - Totale Relationen.pdf>) | 1 | Typisierung der strikten Obermengenrelation zusätzlich von sechs auf drei Zeilen verkürzbar. |
| [5: Funktionen](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 05 - Funktionen.pdf>) | 32 | Weitere Kürzung; bei zwei Abschlüssen fehlt eine Existenzelimination. |
| [6: Injektive Funktionen](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 06 - Injektive Funktionen.pdf>) | 2 | Bei einer Regelanwendung sind die Abhängigkeiten zu berichtigen. |
| [7: Surjektive Funktionen](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 07 - Surjektive Funktionen.pdf>) | 2 | Allgemeine Operator- und Filterregeln aus Band 27 bereits aufgenommen. |
| [8: Bijektive Funktionen](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 08 - Bijektive Funktionen.pdf>) | 8 | Zwei weitere Kürzungen durch Surjektivitäts- und Aussonderungssatz. |
| [9: Auswahlprinzip](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 09 - Auswahlprinzip.pdf>) | 0 | Direkte Mengen-/Funktionssätze; keine zusätzliche Regelkürzung bestätigt. |
| [10: Natürliche Zahlen](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 10 - Natürliche Zahlen.pdf>) | 10 | Vier weitere Kürzungen durch frühere Mengenregeln; historische inaktive Beweise ausgeschlossen. |
| [11: Äquivalenzrelationen](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 11 - Äquivalenzrelationen.pdf>) | 6 | Trägerinklusion einer Äquivalenzklasse zusätzlich verkürzbar; Graphkorrespondenz bereits aufgenommen. |
| [12: Halbordnungen](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 12 - Halbordnungen.pdf>) | 1 | Trägerinklusion eines Hauptfilters von vier auf zwei Zeilen verkürzbar. |
| [13: Schranken, Infima und Suprema](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 13 - Schranken, Infima und Suprema.pdf>) | 2 | Obere und untere Schrankenmenge jeweils von fünf auf drei Zeilen verkürzbar. |
| [14: Paarinfima und Paarsuprema](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 14 - Paarinfima und Paarsuprema.pdf>) | 0 | Teilmengen als Schrankenrelation; passende Schnitt-/Vereinigungssätze sind schon kürzer. |
| [15: Totale Ordnungen](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 15 - Totale Ordnungen.pdf>) | 0 | Paarmengen liegen bereits durch den Paarmengensatz im Grundbereich. |
| [16: Wohlordnungen und Auswahlaxiom](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 16 - Wohlordnungen und Auswahlaxiom.pdf>) | 0 | Aussonderungs- und Bildsätze; Potenzmengenzugehörigkeit wird eliminiert. |
| [17: Ganze Zahlen](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 17 - Ganze Zahlen.pdf>) | 0 | Typisierung der natürlichen Kopie durch den Bildsatz. |
| [18: Rationale Zahlen](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 18 - Rationale Zahlen.pdf>) | 0 | Bildmonotonie, Typisierung und Transitivität. |
| [19: Reelle Zahlen](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 19 - Reelle Zahlen.pdf>) | 21 | Drei bisher zusammengefasst begründete Schnittinklusionen müssen explizit hergeleitet werden. |
| [20: Endliche Mengen](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 20 - Endliche Mengen.pdf>) | 14 | Zwei übersprungene Elementabschlüsse; zusätzlich eine Kürzung durch den Aussonderungssatz. |
| [21: Folgen](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 21 - Folgen.pdf>) | 0 | Allgemeine Folgengraphsätze bereits aufgenommen; guter Zielort für das gemeinsame-Stufe-Lemma. |
| [22: Gerichtete Graphen](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 22 - Gerichtete Graphen.pdf>) | 0 | Graphinklusionen folgen direkt aus Aussonderung oder Durchschnitt. |
| [23: Ungerichtete Graphen](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 23 - Ungerichtete Graphen.pdf>) | 0 | Die verbleibenden Quantorabschlüsse betreffen die Kantensymmetrie. |
| [24: Schlichte ungerichtete Graphen](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 24 - Schlichte ungerichtete Graphen.pdf>) | 0 | Teilmengenformeln stehen nur in Annahmen. |
| [25: Zusammenhängende Graphen](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 25 - Zusammenhängende Graphen.pdf>) | 0 | Keine Teilmengenformel in einer Beweiszeile. |
| [26: Bäume](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 26 - Bäume.pdf>) | 2 | Allgemeine Weg-/Elternsystemsätze bereits aufgenommen; übrige Inklusionen durch bestehende Sätze. |
| [27: Endliche Wörter und Klammerungsbäume](<C:/Latex/Die-Grundlagen-der-Mathematik/output/Bd. 27 - Endliche Wörter und Klammerungsbäume.pdf>) | 10 | Zwei weitere Kürzungen durch schon ausgelagerte Sätze; ein sinnvoller allgemeiner Beweiskern für Band 21. |

## Konkrete zusätzliche Kürzungen

Die folgenden Zahlen bezeichnen explizite Ersatzableitungen. Es werden
nicht lediglich bestehende Zeilen in längere verschachtelte Verweise gepackt.
Bereits umgestellte Anwendungen werden nicht als neue Anwendungen gezählt.

| Band | Unabhängige Kürzungsfälle | Einsparung dieser Vorschläge |
|---|---:|---:|
| 3 | 9 | 22 Zeilen |
| 4 | 1 | 3 Zeilen |
| 5 | 4 | 15 Zeilen |
| 8 | 2 | 12 Zeilen |
| 10 | 4 | 27 Zeilen |
| 11 | 1 | 1 Zeile |
| 12 | 1 | 2 Zeilen |
| 13 | 2 | 4 Zeilen |
| 20 | 1 | 1 Zeile |
| 27 | 2 | 8 Zeilen |
| **Gesamt** | **27** | **95 Zeilen** |

Die frühen Prüfdetails enthalten alle 24 Ersatzableitungen R1–R4 und
S1–S20 mit zusammen 86 eingesparten Zeilen. Die drei zusätzlichen Fälle
aus Band 20 und Band 27 sparen zusammen neun Zeilen. Beispiele daraus:

| Band / Satz | Bisher → vorgeschlagene Fassung | Grund |
|---|---:|---|
| 3.10.2.10 und 3.10.2.11: `A∩B⊆A` bzw. `A∩B⊆B` | jeweils 6 → 3 Zeilen | Das bereits vorher bewiesene Elementlemma liefert direkt den Endpunkt für die Teilmengenregel. |
| 3.7.3.7: Aussonderung liegt in der Grundmenge | 4 → 3 Zeilen | Elementlemma und Teilmengenregel verbinden. |
| 3.12.18: `A⊆C ⇒ A\B⊆C` | 5 → 3 Zeilen | Vorhandene Inklusion `A\B⊆A` und Transitivität. |
| 5.2.5.9: Urbild eines Durchschnitts | 13 → 8 Zeilen | Vorhandene Urbildmonotonie und der allgemeine Schnittmengensatz. |
| 8.2.2.1(H2): Zielbereich liegt im Bild einer Bijektion | 15 → 5 Zeilen | Der schon in Band 7 bewiesene Bildsatz für Surjektionen. |
| 10.2.4.9: Teilmengen einer Nachfolgermenge ohne neues Element | 15 → 6 Zeilen | Nachfolgerdefinition und allgemeiner Satz über eine Adjunktion ohne den neuen Punkt. |
| 20.6.1.4: Cantor–Bernstein-Teilmenge liegt im Ausgangsbereich | 5 → 4 Zeilen | Definition und direkter Aussonderungssatz. |
| 27.2.7.8(H2): Typisierung des verschobenen Konkatenationsblocks | 10 → 5 Zeilen | Allgemeiner Termbildsatz **3.18.1.5**. |
| 27.3.4.12: Ein zulässiger Faserfilter erzwingt einen einzigen Wert | 17 → 14 Zeilen | Allgemeiner Faserwertsatz **7.3.1.25**. |

Weitere Details und die vollständig ausgeschriebenen Ersatzableitungen
für die frühen Bände stehen in der
[Prüfung der Bände 1–13](<C:/Latex/Die-Grundlagen-der-Mathematik/docs/band01-13-teilmengen-pruefdetails-2026-09-13.md>).
Die Fälle aus den Bänden 14–26 stehen in der
[zugehörigen Detailprüfung](<C:/Latex/Die-Grundlagen-der-Mathematik/docs/band14-26-teilmengen-pruefdetails-2026-09-13.md>).

Bei **27.2.7.8(H2)** ist die Abkürzung besonders direkt. Setze
`J=N_<|v|`, `M=N_<(|u|+|v|)×A` und `t(j)=(|u|+j,v(j))`:

1. `u,v∈A*` — Annahme.
2. `[j∈J]` — lokale Annahme mit frischem `j`.
3. `t(j)∈M` — der bereits bewiesene Teil H1, aus 1 und 2.
4. `∀j∈J t(j)∈M` — Implikations- und Allquantoreinführung über 2–3.
5. `{t(j)|j∈J}⊆M` — Termbildsatz 3.18.1.5.

Bei **27.3.4.12** ersetzen die vorhandenen Voraussetzungen in Zeilen 5
und 8 die bisherige vierzeilige Rechnung mit `t≠t∨z=c`: Satz 7.3.1.25
liefert sofort `z=c`. Die Aussage bleibt eine Anwendung in der Baumrekursion.

## Formale Lücken und notwendige Präzisierungen

Diese Befunde sind keine zusätzlichen Zeileneinsparungen. Die Regel entlädt
nur ihre angegebene lokale Elementannahme. Existenzzeugen und sonstige
Grundannahmen werden dadurch nicht automatisch entladen.

| Band / Stelle | Befund und erforderliche Korrektur |
|---|---|
| Band 3: `A∪{a}=A` und `P(∅)={∅}` | Teilweise werden Elementlemmata unmittelbar als Inklusion zitiert. Es fehlt der ausdrücklich begründete Teilmengenabschluss; außerdem sind beim Adjunktionsbeweis die Abhängigkeiten zu berichtigen. |
| 3.12.18 | Die lokale Elementannahme bleibt fälschlich in der Abhängigkeitsliste der fertigen Inklusion stehen. |
| 5.3.2.16, beide Teilmengenrichtungen | Vor dem Teilmengenschluss muss die jeweilige Existenzzeugenannahme 6 entladen werden: `∃E(5,6,12)` bzw. `∃E(5,6,13)`. Erst danach kann die Annahme 4 durch die Teilmengenregel entfallen. |
| Band 6: Bild eines Durchschnitts, zweite Richtung | Die Inklusion bleibt von den Grundannahmen `A⊆M` und `B⊆M` abhängig. Sie dürfen im Schluss nicht aus der Abhängigkeitsliste verschwinden. |
| 19.6.1 und 19.6.3 | Drei Schnittinklusionen werden nur mit der Schnittcharakterisierung begründet. Die Elementargumente über einen äußeren Schnittpunkt bzw. den Abwärtsabschluss sind explizit nachzutragen und mit der Teilmengenregel abzuschließen. |
| 20.3.6.15 | Im Schluss werden H1/H2 ohne lokale `Y`-Annahme von Elementlemmata zu Inklusionen gemacht. Eine ausdrückliche Fassung braucht acht statt vier Schlusszeilen. |

Die Detailberichte geben Quellenzeilen, aktuelle Satznummern,
Abhängigkeitslisten und konkrete Ersatzableitungen an. Diese Korrekturen
sind vor einer neuen Gesamtbilanz eingesparter Zeilen zu berücksichtigen.

## Was aus Band 27 noch sinnvoll vorgezogen werden kann

Die zweite Strukturprüfung erfasst **233 aktuelle Hauptsätze**, **114
explizite Teilbeweisblöcke** und sämtliche **40 aktiven Quellen** von Band 27.
Die bereits verlagerten 46 Hauptsatzstellen und der Teilbeweis H2 werden
nicht erneut gezählt. Ein weiterer Hauptsatz, dessen bestehende Aussage
bereits vollständig unabhängig von Wort-/Baumdefinitionen ist, wurde nicht
gefunden. Die kurzen Abkürzungen `C(H)` oder `M(G)` bezeichnen dort ausdrücklich
Wort- bzw. Baumabschlussbedingungen.

**Ein weiterer sinnvoller allgemeiner Beweiskern ist jedoch die gemeinsame
Stufe einer wachsenden Mengenfolge**, derzeit baumspezifisch in
**27.3.2.11 „Gemeinsame Baumstufe“**. Zielort: Band 21 direkt nach
**21.4.3.2**, bei den wachsenden Mengenfolgen.

Eine geeignete allgemeine Fassung lautet:

\[
\begin{gathered}
D:\mathbb N\to\mathcal P(M),\qquad
\forall j\in\mathbb N\;D(j)\subseteq D(j+1),\\
\exists m\in\mathbb N\;x\in D(m),\qquad
\exists n\in\mathbb N\;y\in D(n)\\
\vdash\quad\exists q\in\mathbb N\;(x\in D(q)\land y\in D(q)).
\end{gathered}
\]

Der Beweis benutzt nur die schon vorhandene Verschachtelung von Mengenfolgen
und natürliche Zahlen. Nach Wahl von `m,n` kann man beispielsweise `q=m+n`
nehmen: Beide Ausgangsstufen liegen in dieser Stufe. Die Existenzzeugen
werden anschließend entladen. Band 27 behält einen kurzen Anwendungssatz,
der die Baumzugehörigkeit in die beiden Stufenzeugen übersetzt.

Eine noch allgemeinere Theorie kleinster abgeschlossener Mengen könnte
weitere Wiederholungen bündeln, erforderte aber eigene Voraussetzungen
und neue Begriffsbildung. Für die jetzige Aufgabe ist die gezielte
Folgenverallgemeinerung wesentlich konkreter. Die bloße Umbenennung der
Wort-/Baumabschlussprädikate wäre keine gültige Auslagerung.

Die [vollständige Liste aller verbliebenen Sätze in Band 27](<C:/Latex/Die-Grundlagen-der-Mathematik/docs/band27-verbleibende-saetze-2026-09-13.md>)
nennt zu jedem Satz Nummer, Titel, Kennung, Quelle und Einordnung.

## Konsequenz für den nächsten Umbau

Die zusätzlichen Arbeiten betreffen **Band 3, 4, 5, 6, 8, 10, 11, 12, 13,
19, 20, 21 und 27**: Lücken schließen, die bestätigten Kürzungen ausführen und den
allgemeinen Mengenfolgensatz in Band 21 formulieren. Die übrigen Bände
wurden mitgeprüft; ihre Inklusionen sind überwiegend bereits durch passende
allgemeine Sätze kürzer begründet. Die neue Teilmengenregel ist dabei ein
Werkzeug für lokale Elementbeweise und kein Ersatz für jeden Satz, in dem
eine Teilmenge vorkommt.
