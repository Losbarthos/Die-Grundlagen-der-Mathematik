# Quotientenabstieg: Umsetzung vom 11. September 2026

Der gemeinsame Existenz- und Eindeutigkeitsschritt ist jetzt in Band 07 bewiesen. Band 11 enthält seine Fassung für Äquivalenzklassen. Neun bisher ausgeschriebene Abstiegsbeweise in Band 17, 18, 41 und 43 verwenden diese Sätze. Die Aussagen und stabilen Bezeichner dieser neun Folgesätze bleiben unverändert.

## Gemeinsame Grundlage

In [Band 07, Abschnitt Abstieg entlang von Surjektionen](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 07 - Surjektive Funktionen.tex:1607>), stehen die folgenden bewiesenen Sätze:

| Bezeichner | Inhalt |
|---|---|
| `RepresentativePairValueUnique` | Ein faserverträglicher Term auf zulässigen Paarrepräsentanten bestimmt genau einen Wert. |
| `RepresentativePairBinaryValueUnique` | Dasselbe für zwei unabhängig gewählte Paarrepräsentanten. |
| `SurjectionFiberValueUnique` | Eindeutiger Wert beim Abstieg entlang einer Surjektion. |
| `SurjectionBinaryFiberValueUnique` | Binäre Fassung des Wertabstiegs. |
| `UniqueRelationFunctionExists` | Eine überall eindeutig erfüllbare Relation definiert eine Funktion. |
| `RepresentativePairFactorization` | Aus einer überdeckenden Paardarstellung und einem faserverträglichen Term entsteht genau eine Funktion. |
| `SurjectionFactorization` | Für eine Surjektion \(q:S\to Q\) und eine auf ihren Fasern konstante Funktion \(h:S\to B\) gibt es genau ein \(F:Q\to B\) mit \(F\circ q=h\). |

Die Funktion wird durch ihren Graphen konstruiert. Es wird keine globale Wahl von Repräsentanten benötigt. Insbesondere sind auch leere Träger durch die Voraussetzungen und Beweise erfasst.

Der davor eingebundene Abschnitt [b07-quotient-normalization.tex](<C:/Latex/Die-Grundlagen-der-Mathematik/tex/b07-quotient-normalization.tex>) beweist die benötigten Quantorenumformungen: beschränkte Paar- und Vierfachquantoren werden in explizite Trägerbedingungen überführt; die abweichende Quantorenfolge bei rationalen Zahlen und die Zusatzbedingung beim Kehrwert werden eigens behandelt. Zwei weitere Sätze übertragen eindeutige Existenz entlang einer punktweisen Äquivalenz. Diese Umformungen sind damit selbst bewiesene Schritte und keine zusätzlichen Schlussregeln.

In [Band 11, Abschnitt Abstieg von Funktionen auf den Quotienten](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 11 - Äquivalenzrelationen.tex:1430>), folgen:

- `QuotientFunctionDescent`: eindeutige Funktion auf dem Quotienten mit vorgeschriebener Zusammensetzung mit der Quotientenprojektion.
- `QuotientValueDescent` und `QuotientBinaryValueDescent`: eindeutige Werte über einem beziehungsweise zwei Klassenrepräsentanten.
- Zwei Hilfssätze, welche die Verträglichkeit bezüglich der Äquivalenzrelation in die benötigte Faserkonstanz übersetzen.

## Umgestellte Folgesätze

Gezählt werden nummerierte Zeilen der Beweistabellen, nicht Druckzeilen oder PDF-Seiten.

| Band | Satzbezeichner | Vorher | Nachher |
|---|---|---:|---:|
| 17 | [IntegerNegationQuotientDescent](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 17 - Ganze Zahlen.tex:793>) | 39 | 12 |
| 17 | [IntegerAdditionQuotientDescent](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 17 - Ganze Zahlen.tex:978>) | 41 | 14 |
| 17 | [IntegerMultiplicationQuotientDescent](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 17 - Ganze Zahlen.tex:1542>) | 65 | 18 |
| 18 | [RationalNegationQuotientDescent](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 18 - Rationale Zahlen.tex:776>) | 23 | 13 |
| 18 | [RationalAdditionQuotientDescent](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 18 - Rationale Zahlen.tex:1002>) | 29 | 18 |
| 18 | [RationalMultiplicationQuotientDescent](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 18 - Rationale Zahlen.tex:1232>) | 27 | 14 |
| 18 | [RationalReciprocalQuotientDescent](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 18 - Rationale Zahlen.tex:2165>) | 25 | 27 |
| 41 | [GroupCompletionOperationQuotientDescent](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 41 - Abelsche Gruppen.tex:885>) | 41 | 33 |
| 43 | [IntegerRingMapQuotientDescent](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 43 - Ringe mit Eins.tex:1323>) | 92 | 23 |
| **Summe** | | **382** | **172** |

Vier gemeinsam genutzte Träger- und Überdeckungshelfer in Band 17 und 18 benötigen zusammen weitere 14 Beweiszeilen. Unter Einschluss dieser Helfer entfallen somit 196 Zeilen in den Anwendungsbänden. Die neue allgemeine Grundlage benötigt zusätzlichen Platz in Band 07 und 11; dies ist keine Aussage über eine Verkürzung des Gesamtbands in Seiten.

Der Kehrwertbeweis ist bewusst um zwei Zeilen länger: Der Repräsentantenbereich für \(\mathbb Q\setminus\{0\}\) und die Bedingung eines von null verschiedenen Zählers werden nun ausdrücklich nachgewiesen. Der Zielbereich bleibt \(\mathbb Q\).

## Prüfung

- Die Kernbeweise, Quantorennormalisierungen, Quotientenfassungen und alle neun Anwendungen wurden unabhängig mathematisch gegengelesen. Geprüft wurden insbesondere die tatsächlichen Schlussregeln, Quantorenfolge, Konjunktionsprojektionen, Gleichheitsrichtungen, frische Zeugen und Entladung der Annahmen.
- Die ursprünglichen Aussagen der neun Folgesätze sowie die vorangehenden speziellen Verträglichkeitsbeweise sind erhalten. Entfernte interne Teilbezeichner besitzen keine verbliebenen Verbraucher.
- Ergänzende endliche Modellprüfungen umfassen 106 unäre und 3226 binäre Instanzen, darunter leere Ausgangsmengen. Zwei Gegenproben zeigen, warum Faserkonstanz beziehungsweise Surjektivität erforderlich sind. Dies ergänzt die ausgeschriebenen Beweise und ersetzt keinen formalen Beweisprüfer.

Die Arbeitsberichte und Sicherungen des Ausgangsstands liegen unter `tmp/quotientenabstieg-2026-09-11/`.

## PDF-Bau und Seitenkontrolle

Alle 49 Einzelbände B00 bis B48 und der Gesamtband wurden neu gebaut. Der Gesamtband umfasst 2.703 Seiten; LaTeX meldet den abgeschlossenen Stand als aktuell. Die abschließenden Verweisprüfungen aller Einzelbände und des Gesamtbands sind bestanden. Ergebnisindizes und Satznummern stimmen zwischen beiden Darstellungen überein.

Die geänderten Abschnitte in Band 07, 11, 17, 18, 41 und 43 wurden seitenweise visuell geprüft. Dabei wurden lange Formeln und Begründungen passend umbrochen sowie getrennte Satz- und Definitionsauftakte zusammengehalten. Nachkontrollen bestätigen die korrigierten Übergänge. Im Gesamtband wurden dieselben 60 Zielseiten gerendert: Ihre vollständigen Textbereiche stimmen pixelgenau mit den freigegebenen Einzelbandseiten überein. Zusätzliche Sichtkontrollen erfassen Seitenzahlen, Titel und wichtige Übergänge im Gesamtband.

Der abschließende Strukturcheck umfasst 5.120 Beweistabellenzeilen in den sieben bearbeiteten Quelldateien. Klammerung und Umgebungen sind ausgeglichen, die 23 neuen Bezeichner sind eindeutig, und es gibt keine verbliebenen Verweise auf die 28 entfernten internen Teilbezeichner.

Die [PDF-Übersicht](<C:/Latex/Die-Grundlagen-der-Mathematik/docs/pdf-index.md>) verlinkt alle 50 endgültigen Dateien im Ordner `output`. Die bestehenden Ausgaben wurden ersetzt und die fünf veralteten Banddateien entfernt. Im Ausgabeordner liegen genau die 50 vorgesehenen PDFs, ohne temporäre Exportdateien oder Sicherungskopien.

Der Exportaudit ist für alle 5.435 PDF-Seiten bestanden: 63.154 interne und 36.324 bandübergreifende Links besitzen gültige Ziele. Ein zusätzlicher Vergleich aller 50 veröffentlichten PDFs mit den geprüften Bauartefakten bestätigt identische dekodierte Seiteninhalte, Seitenzahlen und Seitengeometrien. Das Umschreiben der externen Dateilinks hat diese Eigenschaften der gesetzten Seiten unverändert gelassen.
