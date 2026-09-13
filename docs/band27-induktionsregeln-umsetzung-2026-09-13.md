# Band 27: Induktionsregeln und kürzere Beweise

Umsetzung des [Konzepts vom 13. September 2026](band27-induktionsregeln-konzept-2026-09-13.md).

## Die beiden abgeleiteten Regeln

Unmittelbar nach 27.2.1.16 steht nun **27.2.1.17, Induktionsregel für erzeugte Wörter**
(`GeneratedWordInductionRule`). Die Regel bündelt Anfang, lokalen
Anfügungsschritt und Wortzugehörigkeit. Ihr achtzeiliger Nachweis stützt
sich ausschließlich auf den unmittelbar vorangehenden Induktionssatz.

Nach der Prädikatsinduktion in einer Wortstruktur steht nun
**27.2.6.6, Induktionsregel in einer Wortstruktur**
(`WordStructureInductionRule`). Ihr Nachweis mit neun Zeilen leitet dieselbe
Regelgestalt für beliebige Wortstrukturen aus dem auf W3 beruhenden
Induktionssatz ab. W0–W3 bleiben erhalten; kein neues Axiom wird eingeführt.

Die Begleittexte erläutern feste Parameter, beliebige Schrittvariablen,
die Entlassung lokaler Annahmen und die Verweisschreibweise
`[i,j,k] ⋮ l`. Eine lokale Induktionsannahme darf im Schritt unbenutzt bleiben.
Für eine Eigenschaft natürlicher Zahlen `P(n)` wird weiterhin die vorhandene
Regel **10.4.4.17** verwendet. Die neue Wortregel behandelt Eigenschaften `P(w)`.

## Geänderte Beweise

Die Zahlen zählen Beweiszeilen einschließlich der jeweiligen Teilbeweise.
Die Theoremnummern in dieser Tabelle sind die Nummern nach der Umsetzung.

| Theorem | Vorher | Jetzt | Beweisänderung |
| --- | ---: | ---: | --- |
| 27.2.2.8, Induktion nach der Kardinalzahl einer endlichen Menge | 20 | 6 | Natürliche Kardinalzahl und Zahleninduktion aus Band 10 |
| 27.2.2.13, Die Erzeugungsregeln liefern lückenlose Funktionsgraphen | 25 | 18 | Wortregel mit Graphtypisierung als Induktionsprädikat; Endlichkeit steht bereits fest |
| 27.2.2.15, Jede endliche Folge wird durch die Wortregeln erzeugt | 31 | 27 | Direkte Anwendung der lokalen Zahleninduktionsregel |
| 27.2.6.7, Eindeutige Endzerlegung in einer Wortstruktur | 26 | 23 | Lokaler Schritt ohne benötigte Induktionsvoraussetzung |
| 27.2.6.28, Eindeutigkeit der Wortrekursion | 29 | 18 | Induktion über `F(u)=G(u)`, danach Funktionsextensionalität |
| 27.2.7.17, Assoziativität der Wortkonkatenation | 18 | 16 | Direkter Abschluss mit der abstrakten Wortregel |
| 27.5.2.5, Jedes nichtleere Wort wird von einem Baum geklammert | 21 | 3 | Der bereits konstruierte Linksbaum liefert den Zeugen |
| 27.5.2.6, Existenz einer Klammerung | 19 | 3 | Derselbe Zeuge belegt die Nichtleerheit der Klammerungsmenge |

Diese acht Beweise haben zusammen **114 statt zuvor 189 Beweiszeilen**.
Unter Einbeziehung der 17 Zeilen für die beiden neuen Regeln entfallen
insgesamt 58 Beweiszeilen. Die beiden Klammerungskürzungen nutzen einen
vorhandenen Zeugen und sind unabhängig von den neuen Induktionsregeln.

Der Beweis zur Funktionseigenschaft des Rekursionsgraphen bleibt bei
13 Zeilen: Die punktweise Kurzregel würde hier eine zusätzliche Zeile
erfordern. Die Kardinalitätshilfssätze bleiben ebenfalls erhalten; ihr
Induktionsnachweis ist nun kürzer. Vier nur innerhalb der beiden alten
Klammerungsexistenzbeweise verwendete Hilfssätze wurden entfernt.

Die Erläuterungen zur frühen Erzeugung, zur späteren Wortinduktion und
zur Klammerungsexistenz sowie die Bandübersicht wurden angepasst.

## Prüfung

Die geänderten Induktionsbeweise wurden unabhängig auf Variablenbedingungen,
Annahmenentlassung, Zeilenverweise und die Reihenfolge ihrer Voraussetzungen
geprüft. Die aktive Quellenfolge enthält 467 benannte Deklarationen und
1546 benannte Verweise, ohne fehlende Kennung, Vorwärtsverweis oder doppelte
Deklaration. Die mathematischen Aussagen werden nicht auf spätere
Rekursions- oder Längensätze gestützt.

Band 27 wurde mit LuaLaTeX neu gesetzt (258 PDF-Seiten). Die Querverweisprüfung
ist bestanden: 4619 externe Links führen zu 244 unterschiedlichen Zielen.
38 Seiten mit den geänderten Sätzen und ihren Nachbarn wurden gerendert und
visuell geprüft; die neue abstrakte Regel und der Eindeutigkeitsbeweis
stehen jeweils vollständig auf einer Seite. Die zwei neu entstandenen
Breitenwarnungen wurden behoben. Zwölf bereits bestehende minimale
Breitenwarnungen von 1,40417 pt im unveränderten späten Baumteil bleiben bestehen.

Die abhängigen Einzelbände B28–B46 und B48 sowie die Übersicht B00 wurden
neu gebaut. Alle zugehörigen Verweisprüfungen sind bestanden. Die vier
gerenderten Übersichtsseiten zum Wortaufbau sind ebenfalls visuell geprüft.
Die aktualisierten PDFs von B00, B27–B46 und B48 liegen in `output/`.
Die anschließende Prüfung sämtlicher 49 Einzelband-PDFs ist bestanden:
2848 Seiten, 13784 interne Links und 38583 bandübergreifende Links.

Der Gesamtband wurde in zwei LuaLaTeX-Läufen neu gebaut (2819 PDF-Seiten).
Die Register und Ergebnisnummern stimmen mit allen Einzelbänden überein;
die Verweisprüfung ist bestanden. Die beiden neuen Regeln sowie
Rekursionseindeutigkeit und Assoziativität wurden auch im Gesamtband auf
den PDF-Seiten 1654, 1688, 1705 und 1725 gerendert und visuell geprüft.
Der Gesamtband liegt ebenfalls aktualisiert in `output/`. Seine abschließende
Linkprüfung ist bestanden: **52417 interne Links, keine externen PDF-Verweise**.
