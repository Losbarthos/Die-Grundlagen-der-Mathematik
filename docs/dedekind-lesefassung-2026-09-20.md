# Dedekindscher Rekursionssatz: Überarbeitung der Lesefassung

Stand: 20. September 2026.

Die Lesefassung ist im Aufbau an die aktuellen Fassungen zu
Cantor–Bernstein und zum Mogiljanskaja-Gegenbeispiel angepasst.
Sie umfasst jetzt **9 PDF-Seiten einschließlich Titelblatt**.

## Inhalt

- Einstieg mit zwei verschiedenen Zuständen und der Übergangsregel
  `a → b`, `b → b`. Das Beispiel wird bei admissiblen Relationen,
  der Nullstufe und der Einordnung erneut aufgegriffen.
- Zwei TikZ-Schaubilder: Zuordnung der natürlichen Stellen zu ihren
  Werten sowie Ausschluss eines nur gedachten Zusatzwerts durch
  Fixierung und Minimalität.
- Klar gegliederte Aussage, Beweisidee und vollständiger Prosabeweis.
  Die mathematischen Schritte des bisherigen Beweises bleiben erhalten.
- Einordnung der Eindeutigkeit innerhalb des Graphen und unter allen
  Lösungen; Verhältnis von Induktion und Rekursion; Anschluss an die
  im Hauptband verwendete Rekursionsabbildung.
- Historischer Vergleich mit Dedekinds *Was sind und was sollen die
  Zahlen?* (1888), § 9, Nr. 125–126. Die Originalquelle ist verlinkt:
  [Werkeabdruck, S. 370–372](https://rcin.org.pl/Content/142188/PDF/WA35_176312_15883-3_Art6.pdf#page=36).
  Dedekinds Beweis über endliche Anfangsstücke wird von der hier
  verwendeten Schnitt- und Fixierungskonstruktion unterschieden.
- Direkte Verweise auf die Minimalität des Rekursionskerns, die
  eindeutige Existenz pro Stufe und die Definition der Rekursionsabbildung.

## Dateien und Prüfung

Bearbeitet wurden `tex/b10/dedekind/reading.tex` und der zugehörige
Wrapper `editions/b10-dedekind-reading.tex`. Neu hinzugekommen sind
`tex/b10/dedekind/reading-diagrams.tex` und
`tex/b10/dedekind/original.tex`.

Der Lesetext wurde unabhängig mathematisch und didaktisch geprüft.
Alle neun endgültigen PDF-Seiten wurden gerendert und visuell geprüft;
die beiden Diagramme und die Abschnittsübergänge sind vollständig und
sauber gesetzt. Der LaTeX-Lauf meldet keine übervollen oder untervollen
Boxen und keine ungelösten Referenzen. Die Register- und Linkprüfung
der Dedekind-Ergänzungen ist bestanden.

Aktualisiert wurde ausschließlich die veröffentlichte Lesefassung unter
`output/04 Zahlen und Folgen/Ergänzungen/Dedekindscher Rekursionssatz/`.
Die fünf ausgehenden PDF-Verweise und alle fünf eingehenden Links aus
Überblick, Gesamtband, Band 10 und Beweistabellen sind geprüft. Der
Einstiegsanker `dedekind.reading` bleibt erhalten; ein Neubau dieser
anderen Dokumente war daher nicht erforderlich.
