# Band 27: Wortmenge aus Erzeugungsregeln

Der Beginn von Band 27 folgt jetzt dem Aufbau einer kleinsten abgeschlossenen
Menge. Die Einleitung verbindet dieses Verfahren mit den natürlichen Zahlen
aus Band 10, den endlichen Mengen aus Band 20, den Folgen aus Band 21 und den
beschrifteten Wurzelwegen aus Band 26.

## Konstruktion und Beweisrichtung

Der Umgebungsbereich besteht aus allen endlichen Teilmengen von `N × A`.
Der Schritt `J(w,a) = w ∪ {(card(w),a)}` verwendet ausschließlich die bereits
bekannte endliche Kardinalzahl. Die Wortmenge wird als Durchschnitt aller
Teilmengen dieses Bereichs definiert, die die leere Menge enthalten und unter
allen Schritten abgeschlossen sind. Die Nichtleerheit der Schnittfamilie wird
vor der Definition bewiesen.

Abschluss, Minimalität und ein Induktionsprinzip folgen unmittelbar aus dieser
Konstruktion. Erst anschließend wird bewiesen, dass die erzeugten Mengen genau
die nullbasierten endlichen Folgen sind. Der Hinweg verwendet die
Erzeugungsinduktion; die Rückrichtung verwendet die Kardinalitätsinduktion aus
Band 20 und die Einschränkung eines Funktionsgraphen auf seinen bisherigen
Anfangsabschnitt. Wortlänge und die späteren Strukturaxiome werden dabei nicht
vorausgesetzt.

Die Anfügungsfunktion des Wortmodells führt genau die anfangs festgelegte
Erzeugungsregel aus. Deshalb folgt W3 nun aus der Schnittkonstruktion. Der
bisherige zweite Minimalitätsbeweis über Wortlängen entfällt. W0 bis W3 und
die anschließende abstrakte Induktion und Rekursion bleiben erhalten.

## Quellen

- `tex/b27-word-generated-set.tex`: eigenständige Anfangskonstruktion.
- `tex/b27-word-characterization.tex`: beide Richtungen des Folgenkriteriums.
- `tex/b27-word-graph-helpers.tex` und `tex/b27-word-graph-adjunction.tex`:
  frühe Hilfssätze zum Anfügen an Funktionsgraphen.
- `tex/b27-word-length.tex`: Länge als endliche Kardinalzahl.
- `tex/b27-word-early-minimality.tex`: Übertragung der konstruierten
  Minimalität auf die Anfügungsfunktion.
- `tex/ueberblick/b27.tex`: angepasste Übersicht.

Die Vorkommensdefinition und ihre zusätzliche Prädikatsnotation entfallen.
Die allgemeinen Hilfssätze zu termgebildeten Mengen stehen jetzt erst vor
der Rekursion, wo sie gebraucht werden. Das konkrete Wortmodell bleibt
mengengleich zur bisherigen Darstellung; die für spätere Bände verwendeten
Wort-, Konkatenations- und Rekursionssätze behalten ihre Schnittstellen.

## Prüfung

Die neue Schnittkonstruktion, das Folgenkriterium und der Übergang zu W3 wurden
unabhängig mathematisch gegengelesen. Dabei wurden insbesondere das leere
Alphabet, die leere Folge, die Voraussetzungen der endlichen Kardinalzahl,
die Definitionsbereiche von Funktionen und die Quantorenbindung geprüft.

Die aktive Quellenprüfung umfasst 44 eingebundene Dateien, 469 benannte
Deklarationen und 1.560 benannte Referenzen. Sie findet keine fehlenden
benannten Verweise, keine Verweise auf später eingeführte benannte Ergebnisse
und keine doppelten benannten Deklarationen. Auch in 136 weiteren
Manuskriptdateien gibt es keine Verweise auf die entfernten Vorkommensprädikate.

Band 27 wurde neu gesetzt und mit 258 PDF-Seiten ausgegeben. Die geänderten
Anfangsseiten, der Übergang zu W0 bis W3 und die verschobenen Hilfssätze wurden
visuell kontrolliert; verwaiste Überschriften wurden korrigiert. Der angepasste
Überblick wurde ebenfalls als PDF kontrolliert.

Die betroffenen Folgebände B28 bis B46, B48 und der Überblick B00 wurden mit
den aktualisierten Ergebnissen neu gebaut. Die veröffentlichten 49 Einzelbände
bestehen die Linkprüfung: 13.804 interne und 38.649 externe Links besitzen ihre
Ziele; es gibt keine gedruckten Fehlermarker für unaufgelöste Referenzen.

Die Gesamtausgabe wurde mit 2.819 Seiten neu gesetzt. Ihr Ergebnisindex und
ihre AUX-Satznummern stimmen für alle Bände mit den jeweiligen Einzelbänden
überein; die Verweisprüfung ist bestanden. Einleitung, Wortdefinition,
Erzeugungsinduktion und Wortaxiome wurden zusätzlich in der Gesamtausgabe
visuell kontrolliert.

Buildprotokolle, Quellenprüfung und gerenderte Prüfseiten liegen unter
`tmp/b27-generated-opening/`. Der Abgleich der Gesamtausgabe ist dort als
`audit-main.log` dokumentiert; die PDF-Linkprüfungen stehen in
`publish-standalones.log` und `publish-main.log`.
