# Band 27: Rumpf, Linksbaum und Baumrekursor

Die zweite Überarbeitung ergänzt drei definierte Werkzeuge im bestehenden
Formalismus. Grundlage bleiben die bereits konstruierten Wörter und Bäume
sowie ihre bewiesenen Induktions- und Rekursionssätze.

## Rumpf und Endbuchstabe

`rumpf_A:A+→A*` und `ende_A:A+→A` werden aus der eindeutigen Endzerlegung
gewonnen. Die Iota-Auswahl und das Prinzip der Funktion zu einem typisierten
Term rechtfertigen ihre Funktionsgraphen. Auch für ein leeres Alphabet
werden keine zusätzlichen Existenzannahmen benötigt.

Die Gebrauchssätze behandeln Typisierung, Wiederzusammensetzen,
Identifikation einer gegebenen Endzerlegung, Entfernen des angehängten
Buchstabens, Lesen dieses Buchstabens und die Längenänderung. Die gemeinsame
Kürzungsregel gewinnt aus gleichen angehängten Wörtern die Gleichheit
beider Bestandteile. Der Rumpf darf dabei das Leerwort sein.

Diese Regeln tragen die ausgearbeiteten Adressbeweise: Das Entfernen des
letzten Bits liefert den eindeutigen Adressvorgänger. Die Beweise der
Wurzelwege und der Kinderkennzeichnung erhalten eigene formale Hilfssätze.

Der Adressteil ist in Grundregeln, Wurzelwege sowie Eltern und Kinder
gegliedert. Seine 26 Hilfssätze enthalten 564 formale Tabellenzeilen. Die
beiden bisherigen Teilbeweise für eindeutige Wurzelwege und die
Kinderkennzeichnung verwenden anschließend jeweils sieben Zeilen. Ihre
angezeigten und registrierten Aussagen sowie die IDs sind unverändert.
Die zusätzliche Herleitung wird damit einmal bereitgestellt und kann in
den eigentlichen Strukturaussagen kurz angewendet werden.

Die Abhängigkeiten sind azyklisch: Die Wurzelpfad-Eindeutigkeit benötigt
keine Eltern- oder Kinderregel. Die Eltern- und Kinderregeln setzen einen
verwurzelten Baum ausdrücklich voraus; im Hauptbeweis wird diese Struktur
vor ihrer Anwendung aus der Wurzelpfad-Eindeutigkeit gewonnen.

## Linksbaum

Die Funktion `L_A:A+→T(A)` entsteht aus der Wortrekursion. Als Hilfsfunktionen
werden die Blattbildung und die Blattanfügung zunächst als typisierte
Funktionsgraphen gebildet. Ihre Rechenregeln lauten:

$$L_A(\langle a\rangle)=\operatorname{Blatt}_A(a),\qquad
L_A(u\frown\langle a\rangle)=L_A(u)\triangleleft_Aa.$$

Wortinduktion beweist `L_A(w) ▷_A w`. Der bisherige relationale Existenzsatz
folgt durch Existenzeinführung mit diesem bestimmten Zeugen. Seine alten
Teilresultate bleiben weiterhin zitierbar.

Die Auswertung des Linksbaums ist die Linksfaltung:

$$\mathsf{BinOp}(A,\star),\ w\in A^+
\ \vdash\ \operatorname{ev}_{\star}(L_A(w))=\Pi_{\star}(w).$$

Hier ist keine Assoziativität erforderlich. Der Induktionsschritt verwendet
auf beiden Seiten denselben bisherigen Wert und denselben Endbuchstaben.

## Gemeinsamer Baumrekursor

`Rek_{A,X}(f,g)` bezeichnet die durch die Strukturrekursion eindeutig
bestimmte Funktion. Ihre Voraussetzungen bleiben `f:A→X` und
`g:X×X→X`. Typisierung, Blattregel, Knotenregel und Identifikation werden
einmal allgemein bewiesen. Für eine binäre Operation gibt es zusätzlich
Regeln, die unmittelbar deren Operationszeichen verwenden.

Positionsmenge, Blattwort und Baumauswertung werden als Instanzen dieses
Rekursors definiert. Ihre bisherigen Definition-IDs und Theoremaussagen
bleiben erhalten. Die Gleichungsbeweise benutzen jetzt die gemeinsamen
Regeln. Die grundlegende Konstruktion des Strukturrekursionssatzes wird
weiterhin vollständig benötigt.

## Quellen und Prüfung

- `tex/b27-word-end-operations.tex`: Rumpf und Endbuchstabe.
- `tex/b27-address-paths.tex`: Adress- und Pfadregeln.
- `tex/b27-left-bracketing.tex`: Linksbaum und Klammerungseigenschaft.
- `tex/b27-left-bracketing-evaluation.tex`: Auswertung des Linksbaums.
- `tex/b27-tree-recursor.tex`: allgemeiner Baumrekursor.
- `tex/b27-position-recursor-existence.tex`: Positionsabbildung aus dem Rekursor.
- `tex/ueberblick/b27.tex`: aktualisierte Übersicht.

Die Ausgangsquellen und Registries wurden vor der Bearbeitung unter
`tmp/b27-weitere-konstruktionen/` gesichert. Dort werden auch Quellprüfungen,
Referenzvergleiche, Buildprotokolle und Seitenrenderings abgelegt. Der
Referenzvergleich berücksichtigt sowohl gedruckte Resultatnummern als auch
die tatsächlichen PDF-Sprungziele.

Die mathematische Gegenprüfung der neuen Regeln und der Adressbeweise ist
abgeschlossen. Sie umfasste insbesondere die Richtung der
Gleichheitselimination, die explizite Verwendung von Konjunktions- und
Äquivalenzregeln, die Typisierung aller Rekursionsdaten und die
Abhängigkeiten der Induktionsschritte. Die acht eingebundenen
`b27-*.tex`-Dateien enthalten keine verschachtelten Theoremaufrufe und
keine ungültigen Steuerzeichen.

Alle 304 zuvor vorhandenen benannten Resultate in Band 27 bleiben erhalten;
die neue Fassung enthält 386. Von den geänderten Sprungzielen sind fünf
Verweise in Band 28 und zehn in Band 48 betroffen. Beide Bände wurden neu
gebaut. Der Vergleich aller 21 beziehungsweise 14 Verweise auf Band 27
bestätigt, dass sie weiterhin auf dieselben mathematischen Aussagen
führen. Ihre eigenen Resultatnummern und Sprungziele sind unverändert.

Die Referenzprüfung der Einzelbände B00, B27, B28 und B48 ist bestanden.
Die überarbeiteten Seiten wurden gerendert und visuell geprüft; lange
Formelzellen, fehlende Abstände und abgetrennte Teilüberschriften wurden
nachgebessert. Die zugehörigen Prüfberichte liegen neben den Buildlogs.

Die abschließende Gesamtausgabe wurde erfolgreich mit 2.758 Seiten gebaut;
Band 27 umfasst 200 Seiten. Auch die Referenzprüfung der Gesamtausgabe ist
bestanden: Resultatnummern und Sprungziele stimmen mit den Einzelbänden
überein. Repräsentative Seiten der neuen Definitionen, der verkürzten
Adressbeweise und der Linksbaum-Auswertung wurden zusätzlich in der
Gesamtausgabe gerendert und visuell geprüft.

Die aktualisierten PDFs für B00, B27, B28, B48 und die Gesamtausgabe wurden
in `output/` veröffentlicht. Die anschließende Prüfung des vollständigen
Ausgabeordners ist bestanden: 50 PDFs, 5.545 Seiten, 64.682 interne und
37.330 externe Verknüpfungen. Die Abschlussprotokolle heißen
`audit-final.log` und `publish-final.log` im genannten Prüfverzeichnis.
