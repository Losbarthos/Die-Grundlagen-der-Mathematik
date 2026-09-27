# Klammerungsunabhängigkeit: Lesefassung und Beweistabellen

Stand: 21. September 2026.

Der [Themen- und Aufbauvorschlag](naechste-lesefassung-thema-und-aufbau-2026-09-20.md)
ist als Paar eigenständiger Ergänzungen zu Band 28 umgesetzt.

**Endgültige Aufteilung vom 21. September:** Wie beim Dedekindschen
Rekursionssatz bleibt genau der Hauptsatz im Hauptband: die
Klammerungsunabhängigkeit als Satz **28.2.3.4**. Der Beweisband enthält
die sechs Hilfsresultate und alle sieben Tabellenbeweise. Beim Schlussbeweis
verweist er auf den Hauptsatz in Band 28, ohne ihn erneut zu deklarieren.
Diese Entscheidung ersetzt den zwischenzeitlichen Stand, in dem alle sieben
Aussagen im Beweisband standen. Die folgende Beschreibung berücksichtigt
die endgültige Aufteilung; alle Ausgaben sind gebaut und geprüft.
Die Prüfungen des Zwischenstands und der Erstveröffentlichung sind darunter
ausdrücklich als historische Stände dokumentiert.

## Inhalt und Aufteilung

Die Lesefassung **„Warum wir Klammern weglassen dürfen“** umfasst elf
PDF-Seiten einschließlich Titelblatt.
Sie beginnt mit den fünf Klammerungen
von vier Faktoren und einem Gegenbeispiel mit Subtraktion. Wörter,
Klammerungsbäume und ihre Werte werden getrennt erklärt. Zwei TikZ-Grafiken
zeigen verschiedene Bäume mit gleichem Blattwort sowie die beiden Wege der
Auswertung, die durch die Baum-Normalform miteinander verbunden werden.

Der Prosabeweis führt das Blockgesetz durch Wortinduktion, die Normalform
durch Bauminduktion und daraus die Klammerungsunabhängigkeit vollständig aus.
Die Anwendung auf Funktionskomposition verdeutlicht den Unterschied zwischen
Umklammerung und Vertauschung. Ein Faktor, das Leerprodukt und unendliche
Produkte werden ausdrücklich unterschieden. Die verwendeten Rekursions- und
Induktionsgrundlagen aus Band 27 sind mit Voraussetzungen und Verweisen genannt.

Die Beweistabellen umfassen sieben
PDF-Seiten einschließlich Titelblatt. Sie deklarieren nun sechs
nummerierte Hilfsresultate mit ihren Beweisen: Anfang und Schritt des
Blockgesetzes, das Blockgesetz selbst, Blatt- und Knotenfall der Normalform
sowie die Normalform. Der siebte Beweisblock beweist die Klammerungsunabhängigkeit
und verweist auf deren Aussage in Band 28. Die sechs Hilfsresultate stehen
jeweils mit Aussage, Kontext und vollständiger Tabelle zusammen.
Die drei tragenden Beweisabschnitte verweisen auf die zugehörigen
Erklärungsabschnitte der Lesefassung.

Band 28 und der Gesamtband enthalten den Hauptsatz über die
Klammerungsunabhängigkeit, eine Erläuterung der Linksfaltung und eine
Anmerkung zur Produktschreibweise mit direkten Verweisen auf die beiden
Begleitfassungen. Die Aussagen von Blockgesetz und Baum-Normalform stehen
ebenso wie ihre vier Induktionshilfssätze ausschließlich im Beweisband;
dort stehen auch alle sieben Tabellen. Die Anmerkung erklärt die klammerfreie Schreibweise bei
unveränderter Faktorenfolge und grenzt sie von Vertauschung und Leerprodukt ab.
Die allgemeinen Wort- und Baumgrundlagen bleiben in Band 27. Im Überblick
erhalten sowohl Band 27 als auch Band 28 Zugänge zu den neuen Ergänzungen.

## Identitäten, Quellen und PDF-Ziele

Alle sieben Sätze behalten ihre ursprünglichen Kennungen und Nummern:
**28.2.2.1–28.2.2.3 sowie 28.2.3.1–28.2.3.4**. Der Hauptsatz
`SemigroupBracketingIndependence` mit der Nummer 28.2.3.4 wird ausschließlich
in Band 28 und dessen Einbindung im Gesamtband deklariert. Die übrigen sechs
Deklarationen gehören ausschließlich zum Beweisband. Die Lesefassung
importiert diese sechs Ergebnisse aus dessen Register und den Hauptsatz
zusammen mit ihren sonstigen B28-Verweisen aus dem Hauptbandregister.
Der Beweisband importiert den Hauptsatz ebenfalls aus Band 28. Die Lesefassung
erzeugt weiterhin keine eigenen nummerierten Deklarationen.

Im Hauptband reservieren sechs `\phantomsection`-Aufrufe die früheren
anonymen Anker der ausgelagerten Deklarationen, ohne Satzdeklarationen oder
Registereinträge zu erzeugen. Den siebten Platz belegt wieder der Hauptsatz
selbst. Damit bleiben die fortlaufenden Hyperref-Ziele der späteren
Ergebnisse an ihren bisherigen Positionen. Die Erhaltungskontrolle betrifft
die **340 übrigen Resultate** und den wieder im Hauptband deklarierten
Hauptsatz, zusammen **341 B28-Resultate**. Der am 20. September geprüfte
Bestand von 343 Resultaten enthielt außerdem Blockgesetz und Baum-Normalform.
Die erneute Prüfung bestätigt für alle 341 Resultate unveränderte
Registrierungsdaten, Drucknummern und PDF-Ziele.

Der Ergänzungsaudit kontrolliert die getrennte Zuständigkeit für einen Hauptsatz
in Band 28 und sechs Hilfsresultate im Beweisband. Er prüft ihre
Originalnummern, das Fehlen doppelter Deklarationen sowie die vollständigen
getrennten Importe und die Navigation. Beide Ergänzungen verlinken die
Anmerkung in Band 28 über `bracketing.notation`. Der Schlussbeweis besitzt
das eigene Ziel `bracketing.proof.independence`. Der frühere Anker
`bracketing.statement.SemigroupBracketingIndependence` bleibt unsichtbar
als kompatibles Sprungziel erhalten, erzeugt jedoch keine lokale
Satzdeklaration. Der Hauptband verweist auf die Lesefassung und die
zugehörigen Beweisabschnitte.

Die sieben Deklarationskörper und Tabellen wurden aus dem bestehenden
Arbeitsstand übernommen. Die Erhaltungskontrolle vom 20. September bestätigte **71
Deklarationszeilen und 269 Tabellenzeilen** ohne inhaltliche Änderung.
Alle sieben Tabellen waren nach Vereinheitlichung der Zeilenenden
zeichenidentisch. Der Prüfbericht samt Vergleichsabschnitt liegt lokal unter
`tmp/bracketing-before/`.

Das neue Quellpaket liegt unter `tex/b28/bracketing/`:

- `statements.tex`: die sieben Deklarationsmakros; eines wird nur im Hauptband,
  die übrigen sechs werden nur im Beweisband aufgerufen;
- `reference.tex`: der Hauptsatz, die Notationsanmerkung, Verweise und sechs
  reservierte Ankerpositionen im Hauptband;
- `proofs.tex`: die sechs Hilfssatzdeklarationen und sieben vollständigen
  Tabellen, beim Schlussbeweis mit Verweis auf den Hauptsatz;
- `reading.tex` und `reading-diagrams.tex`: Lesetext und Vektorgrafiken;
- `edition-setup.tex`: getrennte Importe und Register.

Hinzu kommen die beiden Wrapper unter `editions/`, die Linkmakros in
`tex/impl/bracketing-editions.tex` sowie das Build- und Auditpaar
`scripts/build-bracketing-editions.ps1` und `scripts/bracketing-editions.py`.
Gesamtbuild, PDF-Veröffentlichung und Quellinventar berücksichtigen die neuen
Ergänzungen. README, Bandverzeichnis und Bauanleitung sind aktualisiert.

## Abschlussprüfung der endgültigen Aufteilung

Band 28 (225 Seiten), Überblick (112 Seiten), Lesefassung (elf Seiten)
und Beweistabellen (sieben Seiten) sind neu gebaut. Die Ergänzungs- und
Einzelbandaudits sind bestanden. Der Hauptsatz ist genau einmal in Band 28
deklariert; im Beweisband steht seine Nummer nur als Verweis vor dem
Schlussbeweis. Dort sind genau die sechs Hilfsresultate deklariert.

Alle sieben Satzkörper und Beweistabellen sind inhaltlich unverändert.
Für die 341 verbliebenen B28-Resultate stimmen Register, Drucknummern und
PDF-Ziele mit dem Ausgangsstand überein. Der Erhaltungsbericht liegt unter
`tmp/bracketing-revision-2026-09-21/preservation.json`.

Die geänderten Seiten aller vier Ausgaben wurden gerendert und visuell
geprüft. Hauptsatz und vollständige Notationsanmerkung stehen auf PDF-Seite 7
von Band 28; die Übergänge zu den folgenden Beispielen sind sauber gesetzt.
Auch die Beweisüberschrift ohne wiederholte Satzaussage und die geänderten
Verweise in Lesefassung und Überblick sind geprüft. Beide Ergänzungen
haben keine übervollen oder untervollen Boxen und keine unaufgelösten Referenzen.

Band 00, Band 28 und beide Ergänzungen sind im Ausgabeordner aktualisiert.
Ihr Verweisaudit ist bestanden: 57 PDF-Dateien, 2914 Seiten, 13774 lokale
und 38731 dateiübergreifende Verweise. Das Protokoll liegt unter
`tmp/bracketing-revision-2026-09-21/publication-final-volumes.log`.
Auch der Gesamtband ist in zwei vollständigen LaTeX-Läufen gebaut
(2761 Seiten). Der Register-, Nummern- und Verweisaudit einschließlich
aller Einzelbandvergleiche ist bestanden. Hauptsatz und Anmerkung auf
PDF-Seite 1873 sowie die Folgeseite wurden zusätzlich visuell kontrolliert;
alle Beweislinks führen zu den richtigen Zielen. Das Prüfprotokoll liegt
unter `tmp/bracketing-revision-2026-09-21/reference-audit-final.log`.
Die abschließende Gesamtausgabe ist veröffentlicht und geprüft: **58
PDF-Dateien, 5675 Seiten, 64896 lokale und 38771 dateiübergreifende
Verweise**. Alle geprüften Verweisziele sind vorhanden. Das abschließende
Protokoll liegt unter
`tmp/bracketing-revision-2026-09-21/publication-final.log`.

## Prüfung des Zwischenstands mit sieben Aussagen im Beweisband: 21. September 2026

Dieser Zwischenstand wurde durch die anschließend gewünschte Aufteilung
mit einem Hauptsatz im Hauptband und sechs Hilfsresultaten im Beweisband
ersetzt. Die folgenden Ergebnisse gelten nur für diesen Zwischenstand.

Band 28 umfasste 224 Seiten. Alle sieben Klammerungsdeklarationen
waren aus seinem Register und seiner AUX-Datei entfernt. Die sieben
Satzkörper, Tabellen und Resultatregister des Beweisbands sind gegenüber
der ersten Veröffentlichung inhaltlich unverändert; die Lesefassung
importiert nun alle sieben nummerierten Ergebnisse aus dem Beweisband.
Die Erhaltungskontrolle ist unter
`tmp/bracketing-revision-2026-09-21/preservation-intermediate.json` dokumentiert.

Die geänderten Seiten von Band 28, Lesefassung, Beweistabellen und Überblick
wurden gerendert und visuell geprüft. Eine durch die Kürzung alleinstehende
Überschrift des folgenden Satzes 28.2.4.1 wurde mit einem lokalen
Umbruchschutz behoben und erneut geprüft. Die beiden Ergänzungen haben
keine übervollen oder untervollen Boxen und keine unaufgelösten Referenzen.

Der Ergänzungsaudit bestätigt die ausschließliche Registrierung der sieben
Sätze im Beweisband und alle Verweise. Die Referenzprüfungen für Band 00
und Band 28 sind bestanden. Beide Ergänzungen sowie Band 00 und Band 28
sind im Ausgabeordner aktualisiert. Die Verweisprüfung dieser veröffentlichten
Ausgabe ist bestanden: 57 PDF-Dateien, 2913 Seiten, 13774 lokale und
38731 dateiübergreifende Verweise. Das Protokoll liegt unter
`tmp/bracketing-revision-2026-09-21/publication-volumes.log`.

Die damals noch ausstehende Gesamtbandveröffentlichung ist kein Nachweis
für die anschließend geänderte endgültige Aufteilung.

## Prüfung der ersten Veröffentlichung: Stand 20. September 2026

Die folgenden Ergebnisse dokumentieren die erste Aufteilung, bei der die
drei zentralen Aussagen noch zusätzlich im Hauptband standen. Sie sind
keine Abschlussprüfung der endgültigen Aufteilung vom 21. September.

Der Lesetext wurde unabhängig mathematisch geprüft. Die beiden
Induktionsbeweise, Beispiele und Diagramme sind schlüssig; insbesondere
wird die Assoziativität der Wortverkettung nicht mit der erst später
verwendeten Assoziativität der Werteoperation verwechselt.

Alle elf Seiten der Lesefassung und alle sieben Seiten der Beweistabellen
wurden gerendert und visuell kontrolliert. Eine Diagrammbeschriftung und
die Umbrüche am Blattfall und am Schluss wurden dabei verbessert. Die
Begleitfassungen haben keine übervollen oder untervollen Boxen und keine
unaufgelösten Referenzen. Auch die geänderten Seiten von Band 28 und die
betreffenden Übersichtsseiten wurden visuell geprüft. Im Gesamtband wurden
zusätzlich die geänderte Seite und ihre Kontextseite kontrolliert; die sechs
Links von den drei Hauptaussagen führen zu den richtigen Abschnitten und
Beweistabellen.

Der Ergänzungsaudit bestätigt die sieben Identitäten und Originalnummern,
die drei mit dem Hauptband gemeinsamen Aussagen, die getrennten Importe
sowie sämtliche lokalen und dateiübergreifenden PDF-Ziele. Die Lesefassung
erzeugt keine eigenen nummerierten Deklarationen. Die Referenzprüfungen für
Band 00, Band 28 und den Gesamtband sind bestanden. Der abschließende
Gesamtbandbuild umfasst 2761 Seiten; seine Resultatregister und Satznummern
stimmen mit den Einzelbänden überein.

Die beiden Ergänzungen, Band 00, Band 28 und der Gesamtband sind im
Ausgabeordner aktualisiert. Der abschließende Verweisaudit der veröffentlichten
Ausgabe ist bestanden: **58 PDF-Dateien, 5675 Seiten, 64897 lokale und 38770
dateiübergreifende Verweise**. Die Prüfprotokolle liegen unter
`tmp/bracketing-editions/reference-audit-final.log` und
`tmp/bracketing-editions/publication-final.log`.

Die technischen Audits sichern Identitäten, Nummern und Navigation. Sie sind
keine maschinelle Prüfung der mathematischen Schlussregeln.

## Ausgaben

- [Lesefassung](<../output/07 Halbgruppen und Monoide/Ergänzungen/Klammerungsunabhängigkeit/Bd. 28 - Klammerungsunabhängigkeit - Lesefassung.pdf>)
- [Beweistabellen](<../output/07 Halbgruppen und Monoide/Ergänzungen/Klammerungsunabhängigkeit/Bd. 28 - Klammerungsunabhängigkeit - Beweistabellen.pdf>)
