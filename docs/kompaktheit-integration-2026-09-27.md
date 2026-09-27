# Totale Beschränktheit und Kompaktheit in Band 47

## Inhalt und Einordnung

Das neue Kapitel 7 folgt auf die Folgenkompaktheit und steht vor dem
Normenausblick, der zu Kapitel 8 wird. Die bisherige Definition der
Folgenkompaktheit und der Schlussausblick verweisen nun auf den tatsächlich
ausgeführten Kompaktheitszusammenhang.

Der Hauptband enthält drei Definitionen und vier Theoreme:

- endliches Epsilon-Netz, mit Zentren in der betrachteten Teilmenge;
- totale Beschränktheit;
- totale Beschränktheit impliziert Beschränktheit;
- totale Beschränktheit genau dann, wenn jede Folge eine Cauchy-Teilfolge hat;
- Folgenkompaktheit genau dann, wenn der Teilraum vollständig und total beschränkt ist;
- Kompaktheit durch offene Überdeckungen im Teilraum;
- Äquivalenz von Überdeckungskompaktheit, Folgenkompaktheit und Vollständigkeit
  zusammen mit totaler Beschränktheit.

Die leere Menge ist bei Netzen, Folgen und Überdeckungen ausdrücklich
berücksichtigt. Das bisherige diskrete Gegenbeispiel motiviert den neuen
Begriff; die Lesefassung ergänzt die Räume (0,1) und [0,1].

## Trennung der Fassungen

- `tex/b47/compactness/main-result.tex`: kanonische Aussagen und Erläuterungen
  im Hauptband, mit direkten Links zu den zugehörigen Beweisen.
- `tex/b47/compactness/proofs.tex`: vollständige Einzelbeweise in Prosa,
  einschließlich der Auswahlfunktionen und Rekursionen. Drei private
  Hilfssätze tragen eigene Nummern im Bereich 47E: getrennte Folge ohne
  endliches Netz, totale Beschränktheit folgenkompakter Mengen und
  Lebesgue-Zahl in der Kugelformulierung.
- `tex/b47/compactness/reading.tex`: eigenständige Lesefassung mit Motivation,
  Beispieltabelle und vollständiger verständlicher Herleitung aller
  Äquivalenzen; keine konkurrierenden nummerierten Satzdeklarationen.

Die Beweise der neuen Hauptsätze sind aus dem Hauptband ausgelagert.
Die vorhandenen Beweise der früheren Kapitel wurden nicht umorganisiert.
Wie im bisherigen metrischen Band sind die neuen Beweise Prosabeweise;
die Ergänzung heißt deshalb ausdrücklich „Beweise“, nicht „Beweistabellen“.

## Integration

Der Überblick zu Band 47 enthält nun endliche Netze und die drei
Kompaktheitsbeschreibungen. README, Bandverzeichnis, PDF-Index und
Build-Dokumentation verlinken die beiden Ergänzungen. Der allgemeine
Build und die PDF-Publikation berücksichtigen sie ebenfalls.

`scripts/compactness-manifest.json` sichert die bisherigen 62 semantischen
B47-Identitäten samt Resultatnummern und Sprungzielen. Die Ergänzungen
verwenden eigene Registries unter `registry/compactness/`.

## Prüfung

- Unabhängige mathematische Prüfung der drei Quellen: keine gefundenen
  fachlichen Fehler oder zirkulären Abhängigkeiten; siehe
  `docs/compactness-independent-review-2026-09-27.md`.
- Quellen-, Nummerierungs-, Import- und Linkprüfung mit
  `scripts/compactness-editions.py`: bestanden. Alle früheren B47-Nummern
  und Ziele bleiben erhalten.
- Band 47: 33 PDF-Seiten, darunter vier neue Inhaltsseiten; die neue
  Ergänzung und der Übergang zum Normenausblick wurden visuell geprüft.
- Lesefassung: zehn PDF-Seiten, sämtliche Seiten visuell geprüft;
  siehe `docs/compactness-reading-layout-2026-09-27.md`.
- Beweisfassung: acht PDF-Seiten. Ein zu langer Formelabsatz und zwei
  vom folgenden Inhalt getrennte Überschriften wurden im Layout korrigiert.
- Die Logs von Band 47 und beiden Ergänzungen enthalten im korrigierten
  Stand keine Overfull-/Underfull-Meldungen oder ungelösten Verweise.
- Die beiden neuen Überblickszeilen wurden im B00-PDF visuell geprüft.
  Dort vorhandene Overfull-Meldungen betreffen die unveränderten
  Übersichten zu Band 43 und 44.

Die Quellenprüfung ist kein maschineller Beweis in einem Beweisassistenten.

## Abschluss des Gesamtband-Builds

Der Gesamtband wurde mit LuaLaTeX in zwei Durchläufen erfolgreich neu
erstellt (2.740 PDF-Seiten). Der Build-Audit für B00, B47 und main ist
bestanden; er prüfte unter anderem 1.255 externe Links im Überblick,
32 in Band 47 und 248 im Gesamtband. Die vier neuen Kapitel-Seiten
2578 bis 2581 des Gesamtband-PDFs wurden zusätzlich gerendert und
visuell geprüft. Ihre Satznummern stimmen mit dem Einzelband überein.

Die finale Beweisfassung wurde nach beiden Umbruchkorrekturen nochmals
auf allen acht Seiten visuell geprüft; es verbleiben keine offenen
Layoutbefunde. Die veröffentlichten Seiteninhalte von B00, B47 und den
beiden Ergänzungen wurden mit den geprüften Build-PDFs verglichen und
sind unverändert. Die Publikation passt ausschließlich die PDF-Verweise
an die relativen Ausgabeordner an.

Die abschließende Publikation mit
`python scripts/publish-pdfs.py --bands B00 B47 --compactness` ist
erfolgreich abgeschlossen. Überblick, Band 47, Gesamtband, Lesefassung
und Beweisfassung liegen in den vorgesehenen Ausgabeordnern. Die gesamte
veröffentlichte Sammlung besteht damit aus 72 PDFs mit 6.070 Seiten;
der Audit bestätigte 64.525 interne und 44.958 externe PDF-Verweise.
Auch die vier geprüften neuen Seiten des veröffentlichten Gesamtbands
stimmen im Seiteninhalt mit dem gerenderten Build überein.

Es verbleiben keine offenen Arbeitsschritte für diese Ergänzung.
