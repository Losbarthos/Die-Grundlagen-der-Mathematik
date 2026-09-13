# Band 27: formale Konstruktionsregeln für Klammerungen

Diese Notiz dokumentiert die erste Überarbeitung. Der anschließende Ausbau
mit Rumpf, Endbuchstabe, Linksbaum und gemeinsamem Baumrekursor ist in
[Weitere Konstruktionen](band27-weitere-konstruktionen.md) beschrieben.

Die Überarbeitung führt eine definierte Relation und einen definierten
Anfügeoperator ein. Die Beweise bleiben im bestehenden Kalkül mit expliziten
Annahmen, Abhängigkeitsmengen, Satzverweisen und Quantorenschritten.

## Definitionen und hergeleitete Regeln

Die Relation `TreeBrackets` wird durch Mitgliedschaft im bereits konstruierten
Funktionsgraphen definiert:

$$T\triangleright_A w\coloneqq(T,w)\in\operatorname{wort}_A.$$

Ihre Lesart ist »T klammert w«. Die Graphdefinition ist für beliebige Mengen
T und w sinnvoll. Die Baumzugehörigkeit, die Wortzugehörigkeit und die Gleichung
des Blattwortes werden daraus als eigene Sätze gewonnen. Anschließend folgen
die hergeleiteten Blatt- und Knotenregeln:

$$a\in A\vdash\operatorname{Blatt}_A(a)\triangleright_A\langle a\rangle,$$

$$S\triangleright_Au,\ T\triangleright_Av\vdash
\operatorname{Knoten}_A(S,T)\triangleright_A(u\frown v).$$

Für einen Baum T und einen Buchstaben a wird die Blattanfügung definiert:

$$(T\triangleleft_Aa)\coloneqq
\operatorname{Knoten}_A(T,\operatorname{Blatt}_A(a)).$$

Die Voraussetzungen der Definition lauten ausdrücklich
$T\in\mathcal T(A)$ und $a\in A$. Ihre Typisierung wird bewiesen.
Die darauf aufbauende Anfügeregel lautet:

$$T\triangleright_Au,\ a\in A\vdash
(T\triangleleft_Aa)\triangleright_A(u\frown\langle a\rangle).$$

Für keine dieser Regeln wird ein neues Axiom vorausgesetzt.

## Existenzbeweis und bestehende Aussagen

Der neue Hauptsatz `TreeBracketingExistence` hat die Form

$$w\in A^+\vdash\exists T\,(T\triangleright_Aw).$$

Sein Induktionsanfang verwendet die Blattregel; im Schritt wird ein frischer
Zeuge R genommen, durch die Anfügeregel erweitert und anschließend mit
Existenzeinführung und Existenzelimination wieder gebunden. Der relationale
Induktionsschritt enthält zwölf nummerierte Zeilen einschließlich aller
abschließenden Quantorenschritte. Der frühere Induktionsschritt in der
Mengenschreibweise hatte 23 Zeilen.

Die bestehende Aussage `WordBracketingExistence` über die Nichtleerheit von
`Kl_A(w)` folgt aus dem relationalen Existenzsatz. Auch die IDs
`WordBracketingExistenceBase` und `WordBracketingExistenceStep` behalten ihre
Aussagen und bleiben zitierbar. Ihr Mengen-Induktionsschritt umfasst nun zehn
Zeilen. Alle übrigen vorhandenen Resultat-IDs bleiben ebenfalls erhalten.

Die neuen Hilfssätze haben eigene vollständige Beweise. Der Gewinn besteht in
der Wiederverwendbarkeit der Konstruktionsschritte; der Gesamtumfang des Bands
wird durch diesen Aufbau nicht kleiner.

## Quellen und Prüfung

- `tex/impl/commands/words-trees.tex`: Makros `TreeBrackets` und `TreeAppendLeaf`.
- `tex/b27-construction-rules.tex`: Definitionen, Typisierung und Konstruktionsregeln.
- `tex/b27-bracketing-existence.tex`: Brücke zur Klammerungsmenge, relationaler
  Existenzbeweis und bisherige Resultate als Folgerungen.
- `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex`: Einbindung der neuen Blöcke.
- `tex/ueberblick/b27.tex`: Definitionen und Regeln in der Bandübersicht.

Die unabhängige mathematische Prüfung kontrollierte die Prämissen der
Satzinstanzen, Gleichheitsrichtungen, Zeugenbedingungen und
Annahmeabhängigkeiten. Bikonditionale werden im neuen Brückenbeweis ausdrücklich
eliminiert. Der Wortinduktionssatz liefert zunächst seine Allaussage; deren
Anwendung auf ein einzelnes Wort erfolgt durch All- und Implikationselimination.
Die im vorhandenen Kalkül verlangte tatsächliche Abhängigkeit beim Entladen
einer Annahme wird im Induktionsschritt durch Konjunktionseinführung und
-elimination hergestellt.

Die technischen Prüfprotokolle und Seitenrenderings dieses Laufs liegen unter
`tmp/b27-formale-ueberarbeitung/`. Ein Registryvergleich prüft, dass keine
bisherigen IDs entfernt wurden. Geänderte Resultatnummern betreffen nur den
bisherigen Existenzsatz und seine beiden Teilresultate; der einzige externe
Quellverweis darauf steht in der aktualisierten Übersicht.

Zusätzlich wurden die tatsächlichen PDF-Sprungziele aus den AUX-Dateien
verglichen. Acht bestehende Ziele verschieben sich, darunter das Ziel der
Mitgliedschaftsaussage trotz gleichbleibender gedruckter Nummer. Die Prüfung
aller übrigen Einzelband-PDFs fand genau zwei zu aktualisierende Links in
Band 28. Deshalb wurde auch Band 28 neu gebaut; seine mathematische Quelle
erhielt durch diese Überarbeitung keine Änderung. Seine 373 eigenen
Resultat-IDs behalten Nummern, Labels und PDF-Ziele, sodass kein weiterer
Folgeband neu gebaut werden musste. Der Überblick und der Gesamtband wurden
ebenfalls neu erzeugt.

Der abschließende Referenzaudit für B00, B27, B28 und den Gesamtband ist
bestanden. Er bestätigt insbesondere die Übereinstimmung der registrierten
Resultate und ihrer Nummern zwischen sämtlichen Einzelbänden und dem
Gesamtband. Die neuen Beweisseiten wurden im Einzelband vollständig und im
Gesamtband an den Definitionen, Konstruktionsregeln und am Existenzbeweis
visuell geprüft. Band 27 umfasst 153 PDF-Seiten, der Gesamtband 2710.

Die fertigen PDFs für B00, B27, B28 und den Gesamtband liegen im bestehenden
Ausgabeordner `output/`. Der abschließende Audit des gesamten PDF-Bestands
bestand für 50 Dateien mit 5449 Seiten, 63308 internen und 36392 externen
Links. Die beiden korrigierten Verweise aus B28 wurden zusätzlich direkt
in der ausgegebenen Datei auf das Ziel der Mitgliedschaftsaussage geprüft.
