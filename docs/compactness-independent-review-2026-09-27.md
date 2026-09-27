# Unabhängige mathematische Prüfung: Kompaktheit in Band 47

Geprüft am 27. September 2026: `tex/b47/compactness/main-result.tex` (162 Zeilen), `proofs.tex` (336 Zeilen) und `reading.tex` (508 Zeilen). Die Prüfung war lesend; ausschließlich dieser Bericht wurde neu angelegt.

**Ergebnis:** Keine korrekturbedürftigen mathematischen Fehler oder widersprüchlichen Aussagen gefunden. Hauptband, Beweisfassung und Lesefassung stimmen in ihren Definitionen und Ergebnissen überein.

## Geprüfte Punkte

- **Definitionen und Teilraummetrik:** Endliche Netze haben Zentren in K; die Abstände sind dieselben wie bei d_K (`main-result.tex:18–44`). Offene Überdeckungen bestehen aus in K offenen Teilmengen von K (`main-result.tex:115–134`). Die anders geschriebene Kugelnotation B_K(c,r) der Lesefassung bezeichnet ausdrücklich dieselben Teilraumkugeln (`reading.tex:29–47`).
- **Leere Menge:** Das leere Netz, die leere Teilüberdeckung und die vacuösen Folgenaussagen sind zugelassen. Auch das Lebesgue-Lemma gilt mit Radius 1 (`proofs.tex:231`). Kein Argument verlangt unberechtigt einen Punkt der leeren Menge.
- **Getrennte Folge:** Die Wahlfunktion auf den nichtleeren Teilmengen von K und die Rekursion auf endlichen Teilmengen ergeben tatsächlich eine ganze Folge mit paarweisen Abständen mindestens epsilon (`proofs.tex:49–79`). Hier wird keine unendliche Auswahl stillschweigend aus einzelnen Existenzbehauptungen abgeleitet.
- **Cauchy-Teilfolge:** Die Mengen J_n sind unendlich und verschachtelt. Die Auswahl phi(n) aus J_(n+1) passt zu den Radien r_n und liefert für sämtliche m,l >= n die Abschätzung d(a_phi(m),a_phi(l)) < 2r_n (`proofs.tex:89–149`). Die Lesefassung verwendet dieselbe Konstruktion mit I_n = J_(n+1) und erläutert zutreffend, dass die Kugeln selbst nicht verschachtelt sein müssen (`reading.tex:157–215`).
- **Charakterisierung der Folgenkompaktheit:** Beide Richtungen benutzen bereits bewiesene Aussagen; die Vollständigkeit betrifft K mit d_K, und alle Grenzwerte liegen in K (`proofs.tex:168–209`, `main-result.tex:93–110`).
- **Lebesgue-Zahl:** Der Beweis verwendet ausschließlich Folgenkompaktheit und Offenheit. Nach dem Teilfolgenübergang wird korrekt der Radius 1/(phi(j)+1) verwendet; dessen Konvergenz gegen null folgt aus phi(j) >= j (`proofs.tex:230–256`; entsprechend `reading.tex:383–408`).
- **Überdeckungskompaktheit:** Folgenkompaktheit liefert über das Lebesgue-Lemma und ein endliches Netz eine endliche Teilüberdeckung (`proofs.tex:266–284`). Die Rückrichtung berücksichtigt Folgeindizes und erfasst daher auch konstante Folgen. Die Familie aller Kugeln mit endlicher Indexmenge vermeidet eine unnötige Auswahl von Radien; eine endliche Teilüberdeckung würde N endlich machen (`proofs.tex:288–328`).
- **Beispiele:** Die diskreten natürlichen Zahlen sowie (0,1) und [0,1] besitzen die angegebenen Eigenschaften. Die Mittelpunktsnetze der Lesefassung liegen selbst in (0,1) und überdecken trotzdem auch [0,1] mit dem geforderten Radius (`reading.tex:293–318`).
- **Verweise:** Die öffentlichen Formula-IDs der Lesefassung stimmen mit den Aussagen des Hauptbandes überein. Die verwendeten Grundlagen für Rekursion, natürliche Wohlordnung, endliche Vereinigungen und die Unendlichkeit von N sind im Bestand vorhanden. Insbesondere lässt sich der Rekursionssatz aus Band 21 auf die ausdrücklich angegebenen Zustandsmengen anwenden.

## Abhängigkeiten und Prüfgrenze

Die Beweisfolge ist zirkelfrei: getrennte Folge -> Cauchy-Teilfolgenkriterium -> Folgenkompaktheit impliziert totale Beschränktheit -> Charakterisierung durch Vollständigkeit und totale Beschränktheit. Das Lebesgue-Lemma wird unabhängig von Überdeckungskompaktheit bewiesen. Erst danach folgt deren Äquivalenz zur Folgenkompaktheit und damit die dritte Charakterisierung.

Dies ist eine mathematische Quellenprüfung. PDF-Layout, tatsächliche Linkziele und erfolgreiche Kompilierung sind Gegenstand der getrennten Build- und Sichtprüfung.

## Visuelle Prüfung der Beweisfassung

Die nach der Schlussformelkorrektur erzeugte Datei `registry/compactness/_B47-compactness-proofs.pdf` wurde vollständig mit Poppler bei 110 dpi gerendert; alle acht PDF-Seiten wurden als Bilder angesehen. Titelblatt, Formeln, Theoremnummern, Schriften und Seitenzahlen waren lesbar. Es waren keine abgeschnittenen Zeichen, Überlagerungen oder über den Satzspiegel laufenden Formeln sichtbar. Die korrigierte Schlussformel war vollständig und korrekt ausgerichtet.

Die erste Sichtprüfung ergab zwei zu korrigierende Seitenumbrüche: Auf PDF-Seite 3 (gedruckte Seite 2) stand die Abschnittsüberschrift 1.2 allein am Seitenende, auf PDF-Seite 5 (gedruckte Seite 4) entsprechend die Überschrift 1.4. Der folgende Inhalt wurde durch den Platzbedarf des Beweisankers erst auf die nächste Seite verschoben. Als Korrektur wurde ein gemeinsamer Platzbedarf vor der jeweiligen Abschnittsüberschrift empfohlen. Zusätzlich enthielt die letzte Seite nur den kurzen abschließenden Schritt (iii); dies war ein Hinweis auf verbesserbare Seitenausnutzung, kein inhaltlicher Fehler.

Nach den Umbruchkorrekturen wurde der stabile Endstand erneut vollständig gerendert; alle acht Seiten wurden nochmals angesehen. Beide verwaisten Abschnittsüberschriften sind behoben: Abschnitt 1.2 steht nun zusammen mit dem Beweisanfang auf PDF-Seite 4, Abschnitt 1.4 zusammen mit dem zugehörigen Hilfssatz auf PDF-Seite 6. Die Seitennummerierung ist fortlaufend, die Formeln und Verweise bleiben lesbar, und es gibt keine abgeschnittenen Inhalte oder Überlagerungen. Der kurze letzte Beweisschritt steht als vollständiger Absatz auf der letzten Seite und enthält keinen abgetrennten Formelrest.

**Visuelles Endergebnis: bestanden.** Keine offenen Korrekturbefunde für die Beweisfassung. Die Renderbilder liegen unter `tmp/compactness-editions/qa-proofs/`.
