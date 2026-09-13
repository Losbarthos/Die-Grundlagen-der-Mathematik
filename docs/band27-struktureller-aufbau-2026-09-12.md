# Band 27: Endliche Vorkommen und Strukturaxiome

Diese Notiz dokumentiert den ersten Umbau. Die anschließende
[Fortführung mit frühen Axiomen](band27-fruehe-axiome-2026-09-12.md)
ersetzt die hier beschriebene Anordnung als Schlusskapitel und die
damaligen Rekursionsbeweise. Die folgenden Prüfzahlen gehören zur
damaligen Fassung.

Die Überarbeitung verbindet den Wortaufbau mit der Endlichkeitstheorie aus
Band 20 und die Baumkonstruktion mit den Graphenbegriffen der Bände 22–26.
Die vorhandenen Änderungen im Arbeitsbaum wurden als Ausgangspunkt übernommen.

## Mathematische Entscheidung

Gewöhnliche endliche Teilmengen des Alphabets speichern weder Reihenfolge
noch Wiederholungen. Das konkrete Wortmodell besteht deshalb aus endlichen
Teilmengen von `N × A`: einer lückenlosen, eindeutig beschrifteten Menge
markierter Buchstabenvorkommen. Ein Wort ist damit weiterhin als
Funktionsgraph verwendbar, aber diese Charakterisierung ist ein Satz und
nicht mehr der Ausgangspunkt seiner Definition. Die Länge ist unmittelbar
die endliche Kardinalität der Vorkommensmenge.

Diese Änderung bewahrt das bisherige konkrete Modell und damit die
Schnittstellen zu den späteren Bänden. Insbesondere bleiben die Resultat-IDs
für Worttypisierung, Konkatenation, Klammerungsbäume und Auswertung erhalten.
Ein Austausch der Baumcodes wäre für die neue strukturelle Darstellung
nicht erforderlich und würde die Syntaxkonstruktion in Band 48 verändern.

## Aufbau und Beweise

- Endliche Vorkommensmengen, ihr Funktionskriterium und die Verbindung von
  Länge und Kardinalität bilden den Beginn der Worttheorie.
- Die strukturelle Wortinduktion und der Anschluss der Induktion über
  nichtleere Wörter führen auf die Endlichkeitstheorie von Band 20 zurück.
- Eine zweite Konstruktion gewinnt die Wortmenge als Schnitt aller
  abgeschlossenen Teilmengen des Bereichs endlicher Vorkommensmengen.
  Die Regelfamilie benutzt ausschließlich die leere Menge und den Schritt
  `u ↦ u ∪ {(tCard(u), a)}`; die Wortmenge selbst kommt darin nicht vor.
- Die Existenz einer Klammerung wird mit Blattfall, Anfügung und
  Wortinduktion bewiesen. Der Linksbaum liefert weiterhin einen kanonischen
  Klammerungszeugen.
- Ein eigenes Kapitel behandelt Positionsmengen und ihre Graphen. Das
  allgemeine Elternsystem erlaubt beliebige Kinderzahlen; volle geordnete
  Binärbäume treten als Spezialfall auf.
- Das Schlusskapitel charakterisiert Wort- und Baumstrukturen durch
  getrennte Konstruktoren, Injektivität und Induktion. Konstruktion,
  Zerlegung, Rekursion und eindeutiger strukturtreuer Transport werden
  dabei auseinandergehalten.
- Die Übersicht in Band 00 und der Anschluss der Formelcodes in Band 48
  werden an diese Darstellung angepasst.

Die Axiome sind Bedingungen an Strukturen mit gegebenen Mengen und
Abbildungen. Sie postulieren keine weiteren Mengen und keine Auswertung
ohne Existenzbeweis. Die konkreten Modelle des Bands weisen ihre
Erfüllbarkeit nach. Für das leere Alphabet bleibt genau das Leerwort;
es gibt keinen mit Alphabetzeichen beschrifteten Klammerungsbaum.

Die Syntax in Band 48 hat unterschiedliche Konstruktoren und Stelligkeiten.
Ihre Einbettung in volle binäre Baumcodes ist von ihrem eigentlichen
Formelaufbau zu unterscheiden. Insbesondere sind dortige Hilfsmarken keine
zusätzlichen atomaren Formeln.

## Prüfung

Die neuen Wortbeweise, die unabhängige Regelkonstruktion, die allgemeine
Baumdarstellung und die Strukturisomorphismen wurden unabhängig
mathematisch gegengeprüft. Dabei wurden insbesondere die Voraussetzungen
der endlichen Induktion, die Eindeutigkeit der Eltern, die Typisierung der
Rekursion und das leere Alphabet berücksichtigt.

Band 27 wurde mit LuaLaTeX neu gesetzt und umfasst 241 Seiten. Seine
Verweisprüfung bestätigt 3.723 externe Links zu 213 verschiedenen Zielen.
Die 107 im Haupttext des Ausgangsstands gefundenen benannten
Deklarationsschlüssel sind weiterhin vorhanden.

Die geänderten Wortabschnitte, die neue Regelkonstruktion, das Baumbeispiel,
die allgemeinen Elternsysteme und sämtliche 16 Seiten des Schlusskapitels
wurden anhand gerenderter PDF-Seiten visuell kontrolliert. Alle neun
Axiomblöcke bleiben mit Titel, Kontext und Formel auf einer Seite.
Auch die geänderten Übersichtsseiten in Band 00 und die Syntaxbrücke in
Band 48 wurden visuell geprüft; deren neuer Beweis steht vollständig auf
einer Seite.

Die unmittelbar betroffenen Folgebände 28 bis 46, Band 48 und Band 00
wurden neu gebaut und einzeln auf aufgelöste Verweise geprüft. Auch die
abschließende technische Verweisprüfung sämtlicher Einzelbände ist
erfolgreich. Nach der Übernahme in `output/` wurden alle 49 Einzel-PDFs
geprüft: 2.829 Seiten, 13.826 interne und 37.672 externe Links; alle
geprüften Linkziele und gedruckten Referenzen sind aufgelöst.

Der Gesamtband wurde ebenfalls vollständig neu gesetzt und umfasst 2.800
Seiten. Seine Verweisprüfung ist erfolgreich; die Ergebnisregister und
Ergebnisnummern stimmen für sämtliche Bände mit den Einzelausgaben
überein. Die Regelkonstruktion und der Beginn des Axiomkapitels wurden
zusätzlich in der Gesamtband-Ausgabe visuell kontrolliert.

Auch die abschließende Linkprüfung der Gesamtband-Ausgabe ist erfolgreich:
51.548 interne Links und keine externen PDF-Abhängigkeiten. Der geprüfte
Gesamtband wurde unverändert in den Ausgabeordner übernommen.
