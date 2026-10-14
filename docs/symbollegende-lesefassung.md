# Seitenbezogene Symbollegende der Lesefassung

Die Legende ist ausschließlich in `editions/b37-nullproducts-reading.tex`
eingebunden. Sie enthält nur Notationen, die in dieser Lesefassung eingeführt
oder ausdrücklich definiert und erklärt werden. Das Potenzmengensymbol wird
nicht registriert; gewöhnliche lokale Variablen ebenfalls nicht.

Die aktuelle Quellregistrierung umfasst **54 verschiedene Einträge**
(am 1. Oktober 2026 direkt in `symbols.tex` gezählt): insbesondere die Familien
L, D, C und E für S und T, Nullproduktprofile und ihre Ordnungen sowie die
Abbildungen Phi, Phi_2, psi, f, g_p, f_p und tau. Unterschiedliche Indizes
innerhalb derselben Familie (etwa E_r^T und E_{psi(p)}^T) verwenden denselben
Legendeneintrag. Die Notationen für S und T bleiben getrennt. Hinzu kommen
eigene Einträge für die konkrete Dreierhalbgruppe S_Bsp und ihre Familien;
die PDF- und Layoutprüfung dieser Erweiterung ist noch in Arbeit. Jedes Symbol
erscheint pro Seite höchstens einmal, nur bei tatsächlicher Verwendung und
frühestens auf seiner Einführungsseite. Es gibt keine kumulative Liste.

## Ein- und ausschalten

In `tex/b37/nullproducts/symbols.tex` steht der zentrale Schalter:

```tex
\providecommand\NullproductsSymbolLegend{1} % 0 = aus, 1 = an
```

Bei `0` sind Sammlung, Randlegende und Layoutanpassung ausgeschaltet. Andere
Editionen laden dieses Modul nicht.

## Weitere Notation registrieren

Eine Zuordnung wird einmalig in `symbols.tex` angelegt, niemals pro Seite:

```tex
\SymbolLegendDeclareReading{strict-set-T}{\(E_r^T\)}%
  {Elemente mit Profil \(<r\)}
```

Die Argumente sind interne ID, sichtbares Symbol und knappe Definition oder anschauliche Beschreibung. Diese soll die
entscheidende Bedingung bzw. Zuordnung möglichst direkt nennen, statt nur
ein Fachwort zu wiederholen.
Die tatsächliche Einführung wird mit einem Stern markiert:

```tex
\NPOrd*{strict-set-T}{E_r^T}=\ldots
```

Jede weitere Verwendung bekommt dieselbe ID, aber keinen Stern:

```tex
\NPOrd{strict-set-T}{E_{\psi(p)}^T}
```

`\NPOrd`, `\NPRel` und `\NPBin` erhalten die mathematische Klasse des
Symbols; der sichtbare Ausdruck steht unverändert im letzten Argument.
Die Marker liegen zusammen mit dem Symbol im mathematischen Atom.
Bestehende semantische Makros können die Registrierung zentral übernehmen.
Bei expliziten Ausdrücken muss jede inhaltlich zugehörige Verwendung markiert
werden. Bloße Textsuche ist keine zuverlässige Registrierung: Beispielsweise
ist `T^2` innerhalb von `a_T^2` kein Produktquadrat der Halbgruppe T.

Die erste tatsächlich ausgegebene Einführung erzeugt das lokale PDF-Ziel und
Label `slreading:<id>`. Der Link lautet **Einführung, S. N** und führt direkt
zur zugehörigen Einführungsseite in derselben Lesefassung. Beim Publizieren
werden die benannten Legendenziele in explizite PDF-Seitenziele mit `/Fit`
umgewandelt. Dadurch ist die ganze Zielseite sichtbar; die ursprünglichen
benannten Ziele bleiben erhalten. Für unnummerierte
Einführungen wird keine Definitionsnummer erfunden. Die Rolle einer
Abbildung kann schon vor ihrer späteren Konstruktion eingeführt sein; der
Link von f führt deshalb zur ersten Erklärung der gesuchten Abbildung.
Vorschauen vor der Einführung, etwa von 0_T, erzeugen noch keinen Eintrag.

Die allgemeine Implementierung unterstützt weiterhin die bisherigen APIs
`\SymbolLegendDeclare` und `\SymbolLegendDeclareID` für nummerierte
Definitionsverweise. In dieser Lesefassung wird ausschließlich
`\SymbolLegendDeclareReading` mit lokalen Einführungen verwendet.

## Seitenzuordnung und Layout

`tex/impl/symbol-legend.lua` sammelt unsichtbare Marker aus den fertig
zusammengesetzten Seitenboxen unmittelbar vor der Ausgabe. Verschobene
Tabellen und Boxen zählen dadurch auf ihrer tatsächlichen Seite; verworfene
Messboxen und ungewählte mathematische Darstellungsvarianten zählen nicht.
Es werden keine Seitenlisten aus einem früheren Lauf übernommen. Eine
Einführung an beliebiger Stelle einer Seite schaltet den Eintrag für diese
Seite frei. Die physische Seitenreihenfolge wird unabhängig von der gedruckten
Seitennummer erfasst. Auch römische Seitenzahlen sind unterstützt.

Die Legende selbst registriert keine Verwendungen. Für weitere bewusst
ausgenommene Inhalte steht `\SymbolLegendWithoutRecording{...}` bereit.

Der Randbereich ist 42 mm breit und hat 7 mm Abstand zum Text. Die
Lesefassung behält ihre bisherige Textbreite; der Text wird nach innen
versetzt. Einseitig liegt die Legende rechts, zweiseitig am jeweiligen
Außenrand. Einstellbar sind `\SymbolLegendWidth`, `\SymbolLegendGap`,
`\SymbolLegendInnerMargin` und `\SymbolLegendEdgeMargin`.

Für diese Lesefassung ist `\SymbolLegendCompacttrue` gesetzt: Symbol und
Kurzbeschreibung stehen in einem Absatz, der Link in einer eigenen Zeile.
Die Schrift bleibt bei 9/11 pt, der Eintragsabstand beträgt 4 pt. Jeder
Eintrag wird als gemeinsame Box verlinkt: Symbol, Erklärung und Seitenzeile
sind über die ganze Randbreite anklickbar. Benachbarte Klickflächen bleiben
getrennt. Die Farbe
wird lokal auf Schwarz gesetzt. Die Einträge stehen in einer gemeinsamen
Box. Zu große Höhe, zu breite Symbole oder überlaufender Text verursachen
einen ausdrücklichen Fehler; nichts wird abgeschnitten, überlagert oder auf
eine sachlich falsche Folgeseite verschoben.

Normale vertikale LuaLaTeX-Seiten und die vorhandenen Tabellen sind
unterstützt. Direktes `\RawShipout`, PDF-Form-XObjects mit eingebetteten
Symbolen und andere Ausgabepipelines benötigen eine eigene Anbindung.
Markierte Leader-Wiederholungen werden ausdrücklich abgewiesen.

## Kompilieren und prüfen

Die ursprünglichen Bände müssen wie bisher mit aktuellen PDF-, AUX- und
Registry-Dateien unter `registry/` vorliegen. Vom Projektverzeichnis aus:

```powershell
python scripts/nullproducts-editions.py prepare-reading
latexmk -norc -lualatex -interaction=nonstopmode -halt-on-error -file-line-error -jobname=_B37-nullproducts-reading -outdir=registry/nullproducts editions/b37-nullproducts-reading.tex
python scripts/nullproducts-editions.py audit
python scripts/check-symbol-legend.py
```

`latexmk` wiederholt die nötigen Läufe für Labels und Verweise. Die
Symbolseiten selbst stammen bereits aus dem aktuellen Umbruch. Nach dem
ersten Lauf können lokale Seitenverweise noch unaufgelöst sein; veröffentlicht
wird erst der fertige Bau ohne ungelöste Verweise.

Neben der PDF entstehen `*.symbol-legend.json` und `*.symbol-legend.tsv`
mit Verwendungen, Einführungen und sichtbaren Einträgen pro physischer Seite.
Die Prüfskripte benötigen Python, pypdf sowie LuaLaTeX und Poppler; die
Bildprüfung zusätzlich Pillow. Sie bauen isolierte Testdokumente unter
`tmp/` und verändern keine veröffentlichten PDFs.

Die neuen Prüffälle `reading-links` und `reading-compact` kontrollieren lokale
Einführungsziele, Seitenwechsel, unterdrückte und verworfene Inhalte,
mathematische Darstellungsvarianten, doppelte Einführungsmarker, römische
Seitenzahlen und das kompakte Layout. `color-state` prüft die Sichtbarkeit
unabhängig vom Farbzustand beim Seitenumbruch. Weitere Fälle prüfen unter
anderem Beweistabellen, zweiseitigen Satz, ausgeschalteten Zustand und
explizite Überlauffehler. Details stehen in
[tests/symbol-legend/README.md](../tests/symbol-legend/README.md).

Die Prüfung vom 29. September 2026 liegt unter
`tmp/pdfs/local-symbols-2026-09-29/`; die gezielten Regressionsergebnisse
unter `tmp/symbol-legend-reading-tests/` und
`tmp/symbol-legend-compact-tests/`. Die damals geprüfte Lesefassung hat 36 Seiten.
Die mathematischen Inhalte bleiben gegenüber der Fassung vor dieser
Legendenerweiterung unverändert.

## Ergebnis der vollständigen lokalen Registrierung vom 29. September 2026

Die endgültige 36-seitige PDF wurde mit 45 registrierten Notationen und
222 internen Legendenlinks geprüft. Alle Links nennen die richtige gedruckte
Seite und führen zur lokalen Einführung. Jeder sichtbare Eintrag entspricht
exakt einer auf dieser Seite verwendeten, bereits eingeführten Notation.
Auf den zusätzlich gerenderten PDF-Seiten 18, 21, 28 und 32 gab es keine
Überlagerungen oder abgeschnittenen Einträge. Der unabhängige Vergleich
bestätigt identische Textwörter und Textpositionen im Haupttext gegenüber
der Fassung vor dieser Legendenerweiterung.

Bei der Veröffentlichung wurde nur diese Lesefassung ersetzt; die übrigen
71 PDFs im Ausgabeordner blieben unverändert. Die Nachweise heißen
`independent-qa.json` und `publication-preservation.json` im oben genannten
Prüfverzeichnis.


## Direkte Seitenlinks und Kurzdefinitionen (29. September 2026)

Die erste Fassung verlinkte nur die Zeile „Einführung, S. …“. Die benannten
PDF-Ziele waren strukturell vorhanden und korrekt; ein Klick auf das Symbol
oder die Erklärung hatte jedoch kein Ziel. Die vergrößerten Klickflächen
beheben diese Lücke. Zusätzlich löst
`scripts/publish-pdfs.py::rewrite_reading_legend_links` ausschließlich die
Lesefassungs-Legendenlinks zu expliziten `[Seitenobjekt /Fit]`-Zielen auf.
Damit benötigen diese Links keine Auflösung des PDF-Namensbaums durch den
Viewer. Andere interne und externe Verweise behalten ihr Verhalten.

Alle 45 Bedeutungstexte wurden zu Kurzdefinitionen überarbeitet, etwa
E_r^T als Elemente t mit [{t}]_T < r und psi als Zuordnung von [A]_S zu
[Phi(A)]_T. Formeln erhalten bei Bedarf gezielte Zeilenumbrüche; die
Überlaufkontrolle nennt jetzt auch die verursachende Symbol-ID. Der
mathematische Haupttext bleibt unverändert.

Die Fälle `reading-links` und `reading-compact` prüfen nun, dass die gesamte
sichtbare Tinte von Symbol, Erklärung und Seitenverweis in der zugehörigen
Linkfläche liegt und keine benachbarten Linkflächen überlappen.
`tests/test_publish_reading_links.py` prüft direkte Seitenziele auch dann,
wenn sich PDF-Objektnummern beim Kopieren ändern.

Nachweise dieser Überarbeitung liegen unter
`tmp/pdfs/symbol-links-definitions-2026-09-29/` und
`tmp/symbol-legend-tap-tests/`. Die Tests prüfen die PDF-Struktur und die
Klickflächen unabhängig vom Anzeigeprogramm; eine solche Prüfung ersetzt
keinen Gerätetest auf dem reMarkable-Tablet.

Die abschließende unabhängige Prüfung dieser Fassung bestätigt alle 222
expliziten Seitenziele und die vollständige Abdeckung von Symbol und
Erklärung durch getrennte Klickflächen. 543 Fälle mit überstehenden
Schrift-Boundingboxes wurden zusätzlich anhand gerenderter Druckpixel geprüft.
Die vier Sichtproben (PDF-Seiten 18, 21, 28 und 32) sind ohne Überlauf oder
Überlagerung. Wörter und Positionen des Haupttexts sind unverändert.

## Getrennte Beispielnotationen (1. Oktober 2026)

Die achte Anmerkungsrunde unterscheidet die allgemeine Ausgangshalbgruppe S
von der konkreten Dreierhalbgruppe S_Bsp. Dafür sind neun zusätzliche
Einträge registriert: `example-semigroup`, `products-example`,
`profile-example`, `profiles-example`, `nullpreorder-Bsp`,
`lower-family-example`, `lower-set-example`, `fiber-example` und
`strict-set-example`. Damit sind in der Quelle 54 Deklarationen mit 54
verschiedenen IDs vorhanden. Die bisherigen 45 Einträge bleiben erhalten.

Die neuen Familien beschreiben M_Bsp, [A]_Bsp, Q_Bsp und die zugehörigen
L-, D-, C- und E-Mengen. Ein allgemeines S in einem Definitionsabschnitt
bleibt S; innerhalb der Dreierbeispiele wird die konkrete Beispielnotation
verwendet. Der Beispielindex wird einheitlich aufrecht gesetzt. Die
Einführungsmarker und Verwendungen werden weiterhin automatisch der
tatsächlichen Ausgabeseite zugeordnet.

Die veröffentlichte Lesefassung hat **37 PDF-Seiten und 250 Legendenlinks**.
Alle 54 Einführungsziele stimmen mit der automatisch erfassten Seite und
ihrer gedruckten Seitenzahl überein. Auf jeder Seite entspricht die sichtbare
Legende genau den dort verwendeten, bereits eingeführten Symbolen. Es gibt
keine Potenzmengen-Einträge und keine mehrfachen Einträge pro Seite.
Alle Seiten wurden visuell geprüft; die Legenden überlappen weder einander
noch den Haupttext. Die ersten Seiten wurden nach der Beispielumbenennung
neu aufgeteilt, um eine fast leere Seite zu vermeiden.

Die Veröffentlichung erhält die Seiteninhalte und die benannten Ziele
unverändert. Für jeden der 250 Legendenlinks wurde zusätzlich nachgewiesen,
dass seine explizite Zielseite der Einführungsseite im ursprünglichen
LaTeX-PDF entspricht und seine Klickfläche erhalten bleibt. Nachweise und
Seitenbilder liegen unter
`tmp/pdfs/nullproducts-annotations-2026-10-01/`, insbesondere
`publication-preservation-specialized.json` und `reading-final37/`.
Die Angaben zu 36 Seiten und 222 Links weiter oben beziehen sich auf den
geprüften Stand vom 29. September. Die inhaltlichen Änderungen stehen im
[Bericht zur achten Anmerkungsrunde](nullprodukt-lesefassung-anmerkungen-runde8-2026-10-01.md).
