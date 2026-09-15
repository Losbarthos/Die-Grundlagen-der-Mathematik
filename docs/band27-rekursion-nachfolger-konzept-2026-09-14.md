# Band 27: Wortrekursion über Nachfolger und natürliche Zahlen

**Umsetzungsstand:** Der folgende Text dokumentiert das ursprüngliche
Konzept. Die anschließend beauftragte Überarbeitung und ihre Prüfungen
stehen im [Umsetzungsbericht](band27-rekursion-nachfolger-umsetzung-2026-09-14.md).

Prüfung des aktuellen Arbeitsstands vom 14. September 2026, insbesondere
Abschnitt 2.6.2 in `tex/b27-word-axiomatic-recursion.tex`, im Vergleich mit
dem Dedekindschen Rekursionssatz in Band 10. Dieses Dokument ist ein
ausgearbeiteter Änderungsvorschlag; die LaTeX-Dateien und ihre vorhandenen
Änderungen werden durch diese Prüfung nicht umgeschrieben.

## Ergebnis

Die Nachfolgerintuition trägt mathematisch. Für jeden Buchstaben
\(a\in A\) ist

\[
s_a:W\to W,\qquad s_a(u)=s(u,a)
\]

eine eindeutig bestimmte Nachfolgerfunktion. Mehrere Buchstaben ergeben
mehrere Nachfolgerfunktionen. Nach W2 lassen sich sowohl das vorherige Wort
als auch der angefügte Buchstabe aus einem Nachfolger eindeutig zurückgewinnen.
W1 trennt alle Nachfolger vom Anfangswort; W3 liefert die Wortinduktion.
Für ein einelementiges Alphabet ist dies genau die Peano-Struktur.

Der aktuelle Rekursionsbeweis ist in seiner Grundidee bereits eng an Band 10
angelehnt: Auch dort werden abgeschlossene Relationen geschnitten und die
Eindeutigkeit ihrer Werte durch Fixierungsargumente bewiesen. Die als anders
empfundene Methode ist also nicht grundsätzlich neu. In Band 27 verdecken
jedoch die Hilfsdefinitionen und Faserbeweise den Zusammenhang mit dem
Wortaufbau. Der vollständige Rekursionssatz steht erst am Ende dieses Wegs.

Empfehlung: Zuerst die Nachfolgeranalogie, die zwei Rekursionsgleichungen und
die Eindeutigkeit erklären. Für die Existenz anschließend den bereits
bewiesenen Rekursionssatz aus Band 10 auf eine Folge wachsender Zuordnungen
anwenden. Dieser Ansatz ersetzt die Familie aller abgeschlossenen Relationen
und die Faserfilter durch eine stufenweise Konstruktion. Der unten
ausgeführte Beweis benötigt auch für eine abstrakte Wortstruktur keine vorab
definierte Wortlänge und keinen Isomorphismus zum konkreten Wortmodell.

## Was der Satz eigentlich aussagt

Gegeben seien eine freie Wortstruktur \((W,e,s)\) über \(A\), eine Menge
\(X\), ein Anfangswert \(x_0\in X\) und eine Funktion
\(r:X\times A\to X\). Dann gibt es genau eine Funktion \(F:W\to X\) mit

\[
F(e)=x_0,\qquad F(s(u,a))=r(F(u),a)
\quad(u\in W,\ a\in A).
\]

Es wird sowohl die Existenz als auch die Eindeutigkeit bewiesen. Die
Schrittfunktion \(r\) liegt bereits vor; konstruiert wird \(F\). Für die
Zielmenge und ihre Schrittfunktion werden keine Wortaxiome verlangt:
Verschiedene Wörter dürfen denselben Wert erhalten.

Die aktuelle Schreibweise
\(\mathsf{WRec}_A(F;W,e,s;X,x_0,r)\) ist lediglich eine Abkürzung für diese
beiden Gleichungen samt \(F:W\to X\). Sie ist keine zusätzliche Syntax des
Wortaufbaus. Sie kann für die späteren formalen Beweise erhalten bleiben,
sollte aber erst nach der verständlichen Aussage eingeführt werden.

| Natürliche Zahlen | Wörter |
| --- | --- |
| Anfang \(0\) | Anfangswort \(e\) |
| Nachfolger \(n+1\) | Nachfolger \(s(u,a)\), abhängig vom Buchstaben |
| \(f(0)=x_0\) | \(F(e)=x_0\) |
| \(f(n+1)=q(f(n))\) | \(F(s(u,a))=r(F(u),a)\) |

Bei mehreren Buchstaben bestimmt die Anzahl der Schritte noch nicht das
Wort. Die natürlichen Zahlen können aber die Aufbauphasen zählen, während
die Wortargumente die verschiedenen Zweige festhalten.

## Vorschlag für den Einstieg in 2.6.2

> Bei den natürlichen Zahlen führt der Nachfolger von einer Zahl zur
> nächsten. In einer Wortstruktur übernimmt das Anfügen eines Buchstabens
> diese Rolle. Für jeden festgehaltenen Buchstaben \(a\) ist
> \(s_a(u)=s(u,a)\) eine Nachfolgerfunktion. Das Wort \(s(u,a)\) bestimmt
> nach den Wortaxiomen sein vorheriges Wort \(u\) und seinen letzten
> Buchstaben \(a\) eindeutig.
>
> Diesen Aufbau wollen wir nun zur Definition von Funktionen verwenden.
> Wir geben einen Anfangswert \(x_0\in X\) und eine Schrittfunktion
> \(r:X\times A\to X\) vor. Gesucht ist eine Funktion \(F:W\to X\),
> für die
> \[
> F(e)=x_0,\qquad F(s(u,a))=r(F(u),a)
> \]
> gilt. Ihr Wert am Anfangswort steht fest. Beim Anfügen eines Buchstabens
> berechnet \(r\) den neuen Wert aus dem bisherigen Wert und diesem
> Buchstaben. Zum Beispiel müssen für \(a,b\in A\) die Werte
> \[
> F(s(e,a))=r(x_0,a),\qquad
> F(s(s(e,a),b))=r(r(x_0,a),b)
> \]
> entstehen.
>
> Der folgende Rekursionssatz besagt, dass diese Vorgaben genau eine
> Funktion auf ganz \(W\) bestimmen. Zunächst zeigen wir mit Wortinduktion,
> dass zwei solche Funktionen übereinstimmen müssen. Anschließend
> konstruieren wir die gesuchte Funktion schrittweise mithilfe der
> Rekursion über die natürlichen Zahlen aus Band 10.

Hier sollte die vollständige Satzaussage bereits als Ziel sichtbar sein.
Wenn die nummerierte Resultatfolge weiterhin nur rückwärts verweisen soll,
kann diese erste Formulierung als unnummerierte Vorschau stehen; das
nummerierte Existenz-und-Eindeutigkeitsresultat folgt nach den Hilfssätzen.

## Eindeutigkeit vor der Existenz

Seien \(F,H:W\to X\) zwei Funktionen, die dieselben Rekursionsgleichungen
erfüllen. Für \(P(u)\iff F(u)=H(u)\) gilt:

\[
F(e)=x_0=H(e).
\]

Aus \(F(u)=H(u)\) folgt für jeden Buchstaben \(a\)

\[
F(s(u,a))=r(F(u),a)=r(H(u),a)=H(s(u,a)).
\]

Die Wortinduktion liefert \(\forall u\in W\;F(u)=H(u)\), die
Funktionsextensionalität also \(F=H\). Hier wird keine Existenz einer
Lösung vorausgesetzt oder erschlichen: Die Aussage lautet, dass beliebige
zwei Lösungen, falls sie vorliegen, gleich sind.

Der bisherige Satz `WordRecursionTwoSolutionsEqual` steht erst am Beginn
der kanonischen Darstellung und verwendet den fertigen Rekursionssatz.
Seine Aussage kann mit diesem direkten Beweis an den Anfang der Rekursion
gezogen werden. Der bisherige Vergleich mit dem eigens konstruierten
Graphen `G` wird dann zu einer unmittelbaren Anwendung.

## Geprüfter Existenzbeweis durch natürliche Rekursion

### 1. Eine Aufbauphase als gewöhnliche Funktion

Setze \(B=W\times X\). Ein Paar \((u,x)\) hält fest, dass dem Wort
\(u\) der Wert \(x\) zugeordnet wird. Für \(H\subseteq B\) setze

\[
T(H)=\{(e,x_0)\}\ \cup\
\{(s(u,a),r(x,a))\mid (u,x)\in H,\ a\in A\}.
\]

Die zweite Menge ist das Bild von \(H\times A\) unter einer bereits
gegebenen Zuordnung. Nach W0 und der Typisierung von \(r\) liegt sie in
\(B\). Damit ist \(T:\mathcal P(B)\to\mathcal P(B)\) eine gewöhnlich
definierte Funktion; ihre Definition enthält keine Wortrekursion.

### 2. Band 10 liefert die Folge der Stufen

Wende den Dedekindschen Rekursionssatz mit der Zielmenge
\(\mathcal P(B)\), dem Anfangselement \(\{(e,x_0)\}\) und der
Schrittfunktion \(T\) an. Er liefert eine Folge
\(h:\mathbb N\to\mathcal P(B)\). Schreibe \(H_n=h(n)\). Dann

\[
H_0=\{(e,x_0)\},\qquad H_{n+1}=T(H_n).
\]

Anschaulich erfasst \(H_0\) das Anfangswort, \(H_1\) zusätzlich alle
Einbuchstabenwörter und \(H_2\) zusätzlich alle Zweibuchstabenwörter.
Der formale Beweis verwendet diese Längenbeschreibung nicht.

### 3. Die Stufen ergänzen einander widerspruchsfrei

**Aufsteigende Stufen.** Aus \(H\subseteq K\) folgt unmittelbar
\(T(H)\subseteq T(K)\). Außerdem ist \(H_0\subseteq H_1\), weil
\(T(H_0)\) das Anfangspaar enthält. Zahleninduktion liefert deshalb
\(H_n\subseteq H_{n+1}\). Erneute Zahleninduktion liefert
\(H_n\subseteq H_m\) für \(n\le m\).

**Ein Wert je erfasstem Wort.** \(H_0\) ist rechtseindeutig. Ist
\(H\subseteq B\) rechtseindeutig, so auch \(T(H)\):

- Nach W1 kann kein durch Anfügen entstandenes Wort gleich \(e\) sein.
  Das Anfangspaar kann daher mit keinem Schrittwert kollidieren.
- Sind zwei Schrittwörter gleich, also \(s(u,a)=s(v,b)\), so liefert W2
  \(u=v\) und \(a=b\). Aus \((u,x),(v,y)\in H\) folgt dann
  \(x=y\), also \(r(x,a)=r(y,b)\).

Zahleninduktion zeigt die Rechtseindeutigkeit jedes \(H_n\). Zusammen mit
der aufsteigenden Folge bedeutet dies: Eine spätere Stufe behält alle
bisherigen Zuordnungen bei und gibt keinem bereits erfassten Wort einen
zweiten Wert.

### 4. Alle Stufen zu einer Funktion zusammenfassen

Setze

\[
G=\bigcup h[\mathbb N]=\bigcup_{n\in\mathbb N}H_n.
\]

Dies ist eine Menge und eine Teilmenge von \(B\). Liegen
\((u,x)\in H_n\) und \((u,y)\in H_m\), so liegen beide Paare in
der größeren der beiden Stufen. Deren Rechtseindeutigkeit liefert
\(x=y\). Also ist auch \(G\) rechtseindeutig.

Nun zeigt Wortinduktion, dass jedes Wort erfasst wird. Als Prädikat genügt

\[
P(u)\iff \exists n\in\mathbb N\;\exists x\in X\;(u,x)\in H_n.
\]

Der Anfang gilt mit \(n=0\) und \(x=x_0\). Liegt \((u,x)\) in
\(H_n\), so liegt für jedes \(a\in A\) das Paar
\((s(u,a),r(x,a))\) in \(H_{n+1}\). Damit gilt \(P\) für alle
\(u\in W\). Zu jedem Wort gehört folglich genau ein Wert in \(G\).
Nach dem bekannten Funktionskriterium ist \(G:W\to X\).

### 5. Die Funktion erfüllt die Rekursionsgleichungen

Das Anfangspaar gehört zu \(H_0\subseteq G\), also \(G(e)=x_0\).
Für \(u\in W\) liegt \((u,G(u))\) in einer Stufe \(H_n\).
Die nächste Stufe enthält
\((s(u,a),r(G(u),a))\). Somit

\[
G(s(u,a))=r(G(u),a).
\]

Dies beweist die Existenz. Mit dem schon vorher bewiesenen
Eindeutigkeitslemma folgt der vollständige Wortrekursionssatz.

## Warum dieser Weg den gewünschten Aufbau trifft

Die verständliche Hauptlinie lautet: Anfangswert festlegen, alle möglichen
Nachfolger auswerten, diese Aufbauphase über die natürlichen Zahlen
wiederholen und die miteinander verträglichen Zuordnungen zusammenfassen.
Der Übergang zu Paarmengen kommt erst dort, wo die gleichzeitige
mengentheoretische Konstruktion aller Werte benötigt wird.

Die Stufen \(H_n\) werden als Graphen von Funktionen auf Teilmengen von
\(W\) erwiesen; ihre Vereinigung wird als Graph einer Funktion auf ganz
\(W\) erwiesen. Ein beliebiges \(H\subseteq B\), auf das \(T\) angewandt
wird, muss dagegen noch keine Funktion sein. Die Paare speichern jeweils
ein Wort und einen Wert; an dieser Stelle wird keine neue graphentheoretische
Struktur eingeführt. Die Familie aller abgeschlossenen Relationen, ihr
Durchschnitt und die Faserfilter entfallen bei dieser Alternative.

Ein Existenznachweis bleibt erforderlich. Nur die Gleichungen
hinzuschreiben oder auf die eindeutige Endzerlegung zu verweisen, beweist
noch nicht, dass alle Werte gemeinsam eine Funktion bilden. Die Folge
\((H_n)\) erfüllt genau diese Aufgabe unter Verwendung des bereits
bewiesenen Rekursionssatzes aus Band 10.

## Voraussetzungen und Umfang einer Umsetzung

- **Kein Zirkelschluss:** Der Aufbau von \(T\) benutzt nur \(W,e,s,X,x_0,r\)
  und bekannte Mengen- und Funktionskonstruktionen. Die Folge entsteht durch
  Zahlenrekursion. Dass der vereinigte Graph ganz \(W\) erfasst, folgt
  durch Wortinduktion.
- **Keine vorgezogene abstrakte Wortlänge:** Auch der Nachweis, dass jedes
  Wort in einer Stufe erscheint, kommt ohne Längenfunktion aus. Die spätere
  kanonische Darstellung der Wortstruktur wird nicht benutzt.
- **Beliebiges Alphabet:** Bei \(A=\varnothing\) ist \(W=\{e\}\) nach
  W3, und jede Stufe besteht nur aus dem Anfangspaar. Bei unendlichem
  Alphabet können schon die ersten Stufen unendlich viele Paare enthalten.
  Es sind Stufen mit endlich vielen Anfügungsschritten, keine notwendig
  endlichen Graphen. Eine Aufzählung oder Ordnung des Alphabets ist unnötig.
- **Vorhandene Grundlagen:** `DedekindRecursionTheorem` in Band 10,
  `WordStructureInductionRule`, W0–W2, Mengenbilder und Vereinigungen aus
  Band 3 sowie `UniqueValuedGraphFunction` aus Band 5 reichen als
  wesentliche Grundlagen. Band 5 enthält außerdem bereits die Vereinigung
  kompatibler Funktionsgraphen; für deren Anwendung müssten die
  Definitionsbereiche der Stufen ausdrücklich bereitgestellt werden.
- **Konkretes Modell:** Dort ist alternativ eine Auswertung nach Positionen
  mit Zahlenrekursion möglich, weil Länge und Folgendarstellung bereits
  bewiesen sind. Diese Alternative allein deckt noch nicht den allgemeinen
  Satz für beliebige Wortstrukturen ab. Die Stufenkonstruktion oben tut dies.

Für eine Umsetzung sollte 2.6.2 zunächst Rekursionsvorschrift, Satzvorschau,
Beispiele und das direkte Eindeutigkeitslemma enthalten. Die stufenweise
Existenzkonstruktion erhält anschließend einen klar bezeichneten eigenen
Unterabschnitt. Danach folgen die konkrete Wortrekursion und die kanonische
Darstellung. Die spätere Baumrekursion kann bei Bedarf entsprechend auf
ihre Darstellung geprüft werden; sie gehört nicht zum hier ausgeführten
Wortbeweis.

Die neue Existenzkonstruktion ist hier als mathematischer Beweis ausgeführt
und unabhängig gegengeprüft. Sie ist noch nicht in die Lemmon-Tabellen des
Manuskripts übertragen. Eine bestimmte Ersparnis an Beweiszeilen oder
PDF-Seiten wird deshalb nicht behauptet. Bei einer Übernahme sind die
ersetzten Hilfssätze, ihre Verweise, die Nummerierung und die erzeugte PDF
zu prüfen. Der bestehende Beweis wird durch diesen Vorschlag nicht als
fehlerhaft verworfen; der Gewinn liegt in der nachvollziehbaren
Konstruktion und der direkten Wiederverwendung von Band 10.
