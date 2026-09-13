# Band 27: Vorschlag für eine anschaulichere Darstellung

Stand: 11. September 2026. Ergänzende didaktische Musterfassungen auf Grundlage der Bandquelle. Die umgesetzte Überarbeitung innerhalb des vorhandenen Kalküls ist in [Formale Konstruktionsregeln](band27-formale-konstruktionsregeln.md) dokumentiert. Die folgenden sprachlichen Musterbeweise dienen als Erläuterungen und ersetzen keine formalen Ableitungen im Fachband.

## 1. Leitidee: Gegenstand, Aussage, Beweisidee, formale Ausführung

Band 27 führt drei verschiedene Gegenstände eng nebeneinander: Wörter als endliche Funktionsgraphen, Bäume als besonders codierte Wörter und Werte einer Auswertung. Das macht die Darstellung anspruchsvoll. Schon die ersten Sätze über die Konkatenation behandeln Mengenmitgliedschaft, verschobene Graphen, Totalität und Funktionalität, bevor das Zusammenhängen zweier Buchstabenreihen als einfaches Bild sichtbar wird.

Jeder zentrale Abschnitt sollte deshalb mit einem kleinen Beispiel beginnen. Zu jedem Hauptsatz gehören eine Aussage in gewöhnlicher Sprache und ein kurzer mathematischer Beweis. Die anschließende formale Ausführung kann genau dessen Schritte aufgreifen. Dadurch haben auch die technischen Hilfssätze einen erkennbaren Zweck.

Empfohlene Reihenfolge innerhalb eines Hauptresultats:

1. **Bedeutung:** Was sagt der Satz über Wörter oder Bäume?
2. **Präzise Aussage:** Voraussetzungen in einem Satz; anschließend eine übersichtliche Formel.
3. **Beweisidee:** Welche Beobachtung trägt den Beweis?
4. **Beweis:** Die mathematischen Schritte mit den benötigten vorherigen Resultaten.
5. **Formale Ausführung:** Die vorhandene tabellarische Ableitung mit entsprechenden Zwischenüberschriften.

Bei reinen Einführungs- und Eliminationsregeln genügt eine gemeinsame Erklärung für den ganzen Block. Eine zusätzliche Erläuterung vor jeder einzelnen Hilfsregel würde den Band unnötig verlängern.

## 2. Notation: Weniger Wiederholung, erkennbare Bedeutungen

| Gegenstand | Empfohlene Leseschreibweise | Vereinbarung |
| --- | --- | --- |
| Wort | $w=\langle a,b,c\rangle$ | Kurzschreibweise für den Funktionsgraphen $\{(0,a),(1,b),(2,c)\}$; entsprechend für jede endliche Länge. |
| Leeres Wort | $\varepsilon$ | Abkürzung von $\varepsilon_A$, solange das Alphabet feststeht. |
| Aneinanderhängen | $(u\frown v)$ | Das vorhandene Zeichen behalten; notwendige Klammern erhalten. |
| Blatt | $\operatorname{Blatt}(a)$ | Bei festem $A$ Abkürzung von $\operatorname{Blatt}_A(a)$. |
| Neuer Baum aus zwei Teilbäumen | $\operatorname{Knoten}(S,T)$ | $S$ ist der linke, $T$ der rechte Teilbaum; Abkürzung des vorhandenen Konstruktors. |
| Blattwort | $\operatorname{wort}(T)$ | Die Beschriftungen der Blätter von links nach rechts. |
| Auswertung | $\operatorname{ev}_{\star}(T)$ | Den Operatorindex behalten: Der Wert hängt von der gewählten Operation ab. |
| Baumstufe | $\mathcal T_n$ | Lokale Abkürzung von $\mathcal T_{A,n}$ bei festem $A$. |

Diese Schreibweisen sind ausdrücklich Abkürzungen der bestehenden Konstruktionen. Insbesondere ist ein Blatt nicht sein Buchstabe. Die Baumbildung sollte weder mit $\star$ bezeichnet werden, das die Auswertungsoperation bezeichnet, noch mit $\lor$, das im Kalkül bereits die logische Disjunktion bezeichnet.

Die Kürzungen gehören zunächst in die erklärenden Texte. Ob auch die registrierten Formeln verkürzt werden, sollte erst bei ihrer gezielten Überarbeitung entschieden werden; dabei sind die bestehenden Resultat-IDs zu erhalten.

### Ein durchgehendes Beispiel

Für $a,b,c\in A$ setzen wir $L_a=\operatorname{Blatt}(a)$, $L_b=\operatorname{Blatt}(b)$ und $L_c=\operatorname{Blatt}(c)$. Dann bilden wir

$$T_\ell=\operatorname{Knoten}(\operatorname{Knoten}(L_a,L_b),L_c),\qquad
T_r=\operatorname{Knoten}(L_a,\operatorname{Knoten}(L_b,L_c)).$$

Diese beiden Bäume sollte eine Zeichnung unmittelbar nebeneinander zeigen. Sie haben dasselbe Blattwort $\langle a,b,c\rangle$, aber unterschiedliche Baumformen. Auch wenn Buchstaben gleich sind, sind die beiden Baumformen verschieden.

Die konkrete Codierung lässt sich anschließend als beschriftete Zeile erklären:

$$T_\ell=\langle(1,3),(1,1),(0,a),(0,b),(0,c)\rangle.$$

Das erste Zeichen $(1,3)$ bedeutet: »Knoten; die nächsten drei Zeichen bilden den linken Teilbaum.« Dieser linke Teilbaum ist $\langle(1,1),(0,a),(0,b)\rangle$. Das verbleibende Zeichen $(0,c)$ bildet den rechten Teilbaum. Ein Bild mit den drei Bereichen **Kopf — linker Teilbaum — rechter Teilbaum** erklärt die gespeicherte Länge.

Wichtig: $|T_\ell|=5$ zählt hier die Zeichen des Baumcodes. Dagegen zählt $|\operatorname{wort}(T_\ell)|=3$ die Blätter. Diese beiden Längen sollten ausdrücklich gegenübergestellt werden.

Bei der Auswertung entstehen aus den zwei Formen die Ausdrücke $(a\star b)\star c$ und $a\star(b\star c)$. Für ganze Zahlen verdeutlicht beispielsweise $a=8$, $b=3$, $c=2$ den Unterschied: Bei Addition ergeben beide Formen $13$; bei Subtraktion ergeben sich $3$ und $7$. Die Operationen stammen aus den früheren Zahlenbänden. Der allgemeine Satz über die Unabhängigkeit von der Klammerung unter Assoziativität gehört weiterhin nach Band 28.

## 3. Musterfassung: Aneinanderhängen ist assoziativ

Bestehendes Resultat: `WordConcatenationAssociative`, Bandquelle ab Zeile 1617.

**Satz.** Sind $u,v,w$ endliche Wörter über $A$, so gilt

$$((u\frown v)\frown w)=(u\frown(v\frown w)).$$

**Bedeutung.** In beiden Fällen stehen zuerst die Buchstaben von $u$, dann die von $v$ und schließlich die von $w$.

**Beweis.** Schreibe $m=|u|$, $n=|v|$ und $p=|w|$. Nach dem Längengesetz und der Assoziativität der natürlichen Addition haben beide Wörter denselben Definitionsbereich, nämlich die Positionen von $0$ bis ausschließlich $m+n+p$.

Jede solche Position gehört zu genau einem der folgenden drei Blöcke. Die Koordinatengleichungen der Konkatenation liefern auf beiden Seiten dieselben Werte:

| Position | Wert auf beiden Seiten |
| --- | --- |
| $i$ mit $0\leq i<m$ | $u(i)$ |
| $m+j$ mit $0\leq j<n$ | $v(j)$ |
| $m+n+k$ mit $0\leq k<p$ | $w(k)$ |

Die Dreiblockzerlegung der natürlichen Anfangsabschnitte stellt sicher, dass damit jede Position erfasst ist. Gleicher Definitionsbereich und gleiche Werte ergeben nach der Funktionsextensionalität gleiche Wörter. Das gilt auch dann, wenn einer oder mehrere der Blöcke leer sind.

**Gliederung der formalen Ausführung:** gemeinsamer Definitionsbereich — drei Positionsblöcke — Wertevergleich — Funktionsextensionalität.

## 4. Musterfassung: Ein Baum lässt sich eindeutig auseinandernehmen

Bestehende Resultate: `TreeConstructorNoConfusion` ab Zeile 4713 und `TreeConstructorDecomposition` ab Zeile 5715. Die lesbare Gesamtaussage fasst beide zusammen.

**Satz.** Jeder Klammerungsbaum ist entweder ein einzelnes Blatt oder ein Knoten mit einem linken und einem rechten Teilbaum. Im Blattfall ist die Beschriftung eindeutig; im Knotenfall sind beide Teilbäume eindeutig. Die beiden Fälle schließen sich aus.

**Beweis.** Die Existenz einer solchen Zerlegung folgt aus dem Aufbau durch Baumstufen: Die Stufe null ist leer; in jeder folgenden Stufe werden ausschließlich Blätter und Knoten aus Bäumen der vorherigen Stufe aufgenommen.

Für die Eindeutigkeit lesen wir den Code von links nach rechts. Ein Blatt beginnt mit $(0,a)$, ein Knoten mit $(1,|S|)$. Wegen $0\ne1$ können beide Fälle nicht zusammenfallen. Bei gleichen Blattcodes sind die ersten Zeichen gleich; die Eindeutigkeit geordneter Paare liefert gleiche Beschriftungen.

Seien nun zwei Knotencodes gleich. Ihre ersten Zeichen sind dann gleich, also stimmen die dort gespeicherten Längen der linken Teilbäume überein. Nach Entfernen des jeweils einen Kopfzeichens bleiben gleiche Wörter $(S\frown T)=(S'\frown T')$. Der Schnitt nach $|S|=|S'|$ Zeichen ist auf beiden Seiten derselbe. Der bereits bewiesene Satz über Kürzung bei festem Konkatenationsschnitt liefert $S=S'$ und $T=T'$.

**Beweisidee in einem Satz:** Das Kopfzeichen entscheidet den Fall und legt bei einem Knoten den Schnitt zwischen den Teilbäumen fest.

## 5. Musterfassung: Strukturinduktion

Bestehendes Resultat: `FullPlanarBinaryTreeStructuralInduction` ab Zeile 6085.

**Satz.** Eine Eigenschaft gilt für alle Klammerungsbäume, wenn sie die folgenden beiden Bedingungen erfüllt:

1. Sie gilt für jedes Blatt.
2. Gilt sie für zwei Teilbäume, so gilt sie auch für den daraus gebildeten Knoten.

**Beweis.** Wir zeigen durch gewöhnliche Induktion über $n$, dass die Eigenschaft für jeden Baum der Stufe $\mathcal T_n$ gilt. Die Stufe $\mathcal T_0$ ist leer, sodass dort nichts zu zeigen ist. Ein Baum der Stufe $\mathcal T_{n+1}$ ist entweder ein Blatt oder ein Knoten aus zwei Bäumen der Stufe $\mathcal T_n$. Im ersten Fall gilt die erste Voraussetzung. Im zweiten Fall gilt die Eigenschaft nach der Induktionsannahme für beide Teilbäume; die zweite Voraussetzung liefert sie für den Knoten. Da jeder Klammerungsbaum in irgendeiner Stufe liegt, gilt die Eigenschaft für alle Klammerungsbäume.

Ein kleines Schema **Blatt prüfen — zwei bereits geprüfte Teilbäume verbinden** sollte vor dem Stufenargument stehen. So erklärt das Stufenargument, warum die anschauliche Beweismethode zulässig ist.

## 6. Musterfassung: Jedes nichtleere Wort besitzt eine Klammerung

Bestehendes Resultat: `WordBracketingExistence` ab Zeile 11211.

**Satz.** Zu jedem nichtleeren Wort gibt es einen Klammerungsbaum, dessen Blätter von links nach rechts genau dieses Wort ergeben.

**Beweis durch Wortinduktion.** Zum Wort $\langle a\rangle$ passt der Baum $\operatorname{Blatt}(a)$.

Sei nun $u$ ein nichtleeres Wort und $T$ ein Baum mit $\operatorname{wort}(T)=u$. Hängen wir den Buchstaben $a$ an $u$ an, bilden wir entsprechend den Baum $\operatorname{Knoten}(T,\operatorname{Blatt}(a))$. Der Konstruktorabschluss stellt sicher, dass dies wieder ein Klammerungsbaum ist. Nach den Rekursionsgleichungen des Blattwortes gilt

$$\operatorname{wort}(\operatorname{Knoten}(T,\operatorname{Blatt}(a)))
=(\operatorname{wort}(T)\frown\langle a\rangle)
=(u\frown\langle a\rangle).$$

Damit bleibt die Behauptung beim Anhängen eines Buchstabens erhalten. Die Wortinduktion liefert sie für alle nichtleeren Wörter. Der konstruierte Baum ist jeweils die vollständig nach links geklammerte Form.

## 7. Strukturrekursion verständlich aufteilen

Das Resultat `FullPlanarBinaryTreeRecursion` beginnt ab Zeile 7716. Seine Bedeutung lässt sich vor der technischen Konstruktion so formulieren:

**Satz.** Sei $f:A\to X$ eine Vorschrift für die Werte der Blätter und $g:X\times X\to X$ eine Vorschrift zum Zusammenführen zweier Teilbaumwerte. Dann gibt es genau eine Abbildung $E:\mathcal T(A)\to X$ mit

$$E(\operatorname{Blatt}(a))=f(a),\qquad
E(\operatorname{Knoten}(S,T))=g(E(S),E(T)).$$

**Beweisplan für die Existenz.** Auf der leeren Stufe beginnt man mit der leeren Abbildung. Stufenweise werden Blattwerte durch $f$ und Knotenwerte durch $g$ festgelegt. Drei Punkte sind nachzuweisen: eindeutige Zerlegung verhindert widersprüchliche Wertzuweisungen innerhalb einer Stufe; aufeinanderfolgende Stufen stimmen auf ihrem gemeinsamen Bereich überein; die Vereinigung der Abbildungen ist auf der gesamten Baummenge definiert. Der vorhandene formale Beweis führt diese Schritte aus. Die bloße Formulierung »rekursiv definieren« wäre an dieser Stelle kein Existenzbeweis, weil die Zulässigkeit dieser Rekursion gerade erst bewiesen wird.

**Vollständiger Beweis der Eindeutigkeit.** Seien $E_1,E_2$ zwei Abbildungen mit den geforderten Gleichungen. Durch Strukturinduktion zeigen wir $E_1(T)=E_2(T)$. Für jedes Blatt liefern beide Abbildungen denselben Wert $f(a)$. Stimmen sie auf $S$ und $T$ überein, folgt

$$E_1(\operatorname{Knoten}(S,T))
=g(E_1(S),E_1(T))
=g(E_2(S),E_2(T))
=E_2(\operatorname{Knoten}(S,T)).$$

Damit stimmen die Abbildungen auf jedem Baum überein. Da sie denselben Definitionsbereich haben, sind sie gleich.

## 8. Reihenfolge einer Überarbeitung

Zuerst die Einführung und die Abschnittseinstiege um das durchgehende Beispiel ergänzen. Anschließend die vier Musterfassungen zu Konkatenation, Baumzerlegung, Strukturinduktion und Klammerungsexistenz in den Fachband übertragen. Danach den langen Rekursionsbeweis nach dem genannten Beweisplan gliedern und die Positionsadressen durch eingezeichnete Links-/Rechtswege erklären.

Die zugrunde liegende Codierung kann dabei bestehen bleiben: Ihre gespeicherte Länge liefert bereits einen sehr anschaulichen Eindeutigkeitsbeweis, sobald man Kopf und Teilbaumblöcke sichtbar macht. Eine umfassende Neucodierung würde neue Beweisarbeit verursachen; für die hier beschriebenen Verbesserungen ist sie nicht erforderlich.
