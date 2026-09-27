# Ergänzende Tabellenbeweise zur Lesefassung der formalen Differenzen

Stand: 21. September 2026.

Die ergänzenden Aussagen der Gruppenlesefassung erhalten eigene formale
Herleitungen im Beweisband zu Band 41. Der Zahlenband und die Gruppenlesefassung
verwenden dabei dasselbe konkrete Ganzzahlmodell; der Vergleich mit der
allgemeinen Differenzenkonstruktion wird ausdrücklich bewiesen.

## Inhalt und Lesepfad

Der Beweisband beginnt mit einem verlinkten Lesepfad und umfasst vier Kapitel:

1. Die bereits ausgelagerte allgemeine Konstruktion und der Einbettungssatz.
2. Zwei unabhängige Differenzenrichtungen: Produktmonoid, Produktgruppe,
   Konstruktion der Klassenabbildung, Bijektivität und Operationserhaltung;
   anschließend Vergleich mit dem Ganzzahlmodell aus Band 17 und Übergang
   zu zwei Ganzzahlkoordinaten.
3. Das Maximum auf `{0,1}`: zunächst Träger, Verknüpfung und Monoidgesetze,
   danach die vier Operationswerte, fehlende Kürzbarkeit und ein vollständiger
   Gegenbeweis zur Transitivität der Kreuzsummenrelation.
4. Notwendige Einbettungsbedingungen: Kürzung in einer Zielgruppe,
   Rückschluss über einen injektiven Homomorphismus, Kommutativität bei
   abelscher Zielgruppe und die abschließende Existenzcharakterisierung.

Die Lesefassung verlinkt die zugehörigen Endergebnisse. Der Modellvergleich
erläutert ausdrücklich die Abbildung von einer allgemeinen natürlichen
Differenzenklasse auf die entsprechende Ganzzahlklasse aus Band 17.

## Tabellenform und Abhängigkeiten

Die neuen Beweise verwenden die eingeführten `tabproof`-Umgebungen mit
offenen Annahmen, Schrittnummer, Formel und Begründung. Die Begründungen
bestehen aus eingeführten Schlussregeln oder Verweisen auf zuvor bewiesene
Sätze beziehungsweise vorhandene Definitionen und Strukturaxiome.
Neue Hilfssätze stehen mit ihren eigenen Tabellen vor ihrer ersten Verwendung.
Es werden keine neuen Beweisregeln oder Axiome eingeführt.

Quantorenschritte enthalten die tatsächlichen Matrizen. Paarzeugen werden
einzeln eingeführt und entladen; ihre Trägertypen werden vor Existenzschlüssen
angegeben. Gerichtete Gleichheitseinsetzungen erhalten bei Bedarf einen
vorherigen Symmetrieschritt. Erklärende Prosa und Teilüberschriften stehen
außerhalb der Schlusszeilen.

Die unabhängige Gegenprüfung betraf insbesondere die Repräsentantenfaktorisierung,
die Abbildung auf Produktklassen, den Modellvergleich, die eingeschränkte
Maximumsordnung und die notwendigen Bedingungen einschließlich aller
Existenzzeugen des Ziels.

## Gezielte Berichtigungen verwendeter Vorstufen

Bei der Prüfung unmittelbar verwendeter Beweise wurden zusätzlich berichtigt:

| Quelle | Tabellen | Berichtigung |
| --- | --- | --- |
| Band 15 | `TotalOrderPairMaximumExistence` | Vier Symmetrieschritte vor gerichteter Gleichheitseinsetzung; explizite Abhängigkeit vom Ordnungsrahmen. |
| Ergänzung zu Band 17 | `IntegerClassInZ`, Klassenkriterium innerhalb `IntegerClassEquality`, `IntegerPairRepresentative` | Gerichtete Einsetzungen, einzeln getypte Paarzeugen, zwei Existenzschlüsse und getrennte Zeugenentladung. |
| Ursprüngliches Kapitel der Ergänzung zu Band 41 | `GroupCompletionClassInCarrier`, `GroupCompletionClassEqualityViaRelation`, Schluss von `GroupCompletionRepresentative` | Dieselben expliziten Gleichheits- und Zeugenführungen für das allgemeine Modell. |

Die Aussagen und ihre semantischen IDs bleiben unverändert. Das ursprüngliche
Ganzzahl-Migrationsmanifest bleibt erhalten; die drei gezielten Tabellenänderungen
werden mit ursprünglichem und korrigiertem Hash in
`scripts/integers-proof-corrections-2026-09-21.json` separat geprüft.
Eine vollständige Nachprüfung aller älteren Bände wird damit nicht behauptet.

## Quellen und Prüfungen

Die neuen Tabellen stehen in `tex/b41/differences/product-example.tex`,
`product-integers.tex`, `maximum-counterexample.tex` und
`necessary-conditions.tex`. Der Einstiegspunkt
`editions/b41-differences-proofs.tex` bindet sie nach der ursprünglichen
Konstruktion ein. Ihre Nummern beginnen in den zusätzlichen Kapiteln mit
`41E.2`, `41E.3` und `41E.4`.

`scripts/differences-supplements.py` prüft die Tabellenabdeckung aller neuen
Sätze, die zeitlich vorherige Definition oder Herleitung lokaler Verweise
und die zulässige Syntax der Begründungsfelder.
`scripts/proof-dependency-audit.py` prüft frühere Zeilenzitate und die
gedruckten offenen Annahmen einschließlich ihrer Entladung.
Das bestehende Editionsaudit prüft zusätzlich die Formeln und Identitäten
der ursprünglichen Konstruktion, die neuen Registereinträge, die Importe
und die PDF-Verweise. Diese Prüfungen ergänzen die mathematische Gegenprüfung;
sie sind kein maschineller Beweisassistent.

Die stabilen Ausgabepfade bleiben:

- `output/08 Gruppen/Ergänzungen/Formale Differenzen/Bd. 41 - Formale Differenzen - Lesefassung.pdf`
- `output/08 Gruppen/Ergänzungen/Formale Differenzen/Bd. 41 - Formale Differenzen - Beweistabellen.pdf`
- Für die berichtigten Ganzzahlvorstufen:
  `output/04 Zahlen und Folgen/Ergänzungen/Ganze Zahlen/Bd. 17 - Ganze Zahlen - Beweistabellen.pdf`

## Ergebnis des Schlussdurchgangs

Die Ergänzungen umfassen folgende neue Tabellen:

| Teil | Neue Aussagen und Definitionen | Tabellen | Beweiszeilen |
| --- | ---: | ---: | ---: |
| Allgemeines Produkt und natürliche Spezialisierung | 35 | 34 | 466 |
| Vergleich mit dem Ganzzahlmodell und dem Ganzzahlgitter | 31 | 28 | 331 |
| Maximum-Gegenbeispiel | 32 | 27 | 236 |
| Notwendige Bedingungen und Existenzcharakterisierung | 13 | 13 | 199 |
| **Gesamt** | **111** | **102** | **1.232** |

Darunter sind 102 bewiesene Sätze und neun Definitionen. Zusammen mit den
28 ursprünglichen Tabellen enthält der Beweisband zu Band 41 jetzt
**130 Tabellen auf 106 PDF-Seiten**. Die Lesefassung umfasst elf Seiten.
Der berichtigte Beweisband zu Band 17 umfasst 102 Seiten; seine Lesefassung
bleibt bei 17 Seiten. Der Gesamtband umfasst weiterhin 2.666 Seiten.

Der vollständige Editionsbau, beide Editionsaudits und das reguläre Bauaudit
für Band 15, 17, 41 sowie den Gesamtband haben bestanden. Sämtliche 43
ursprünglichen Nummern und automatischen PDF-Anker des B41-Beweisbandes
wurden zusätzlich gegen den gesicherten Ausgangsstand verglichen und bleiben
erhalten. Ebenso bleiben alle 85 öffentlichen Ganzzahl-IDs unverändert.
Die Quellenprüfung der neuen Tabellen meldet keine offenen manuellen Fälle
bei der Annahmenbuchführung und keine Rückgriffe auf noch unbewiesene lokale
Sätze. Der Quellaudit findet keine unzulässigen Steuerzeichen.

Die neue Lesefassung, alle zusätzlichen Beweisseiten und die gezielt
berichtigten alten Beweisseiten wurden gerendert und visuell geprüft.
Die beiden B41-Ausgaben haben keine überbreiten Zeilen und keine undefinierten
Verweise. Die letzten Korrekturen halten Abschnittsüberschriften und
Beweisanfänge sowie zusammengehörige Schlusszeilen zusammen.

Die aktualisierten Band- und Ergänzungsdateien sowie der neu gebaute
Gesamtband sind unter den bestehenden Pfaden in `output/` veröffentlicht.
Die korrigierten Maximumsseiten wurden auch im Gesamtband auf PDF-Seiten
1040–1041 visuell geprüft. Die abschließende Linkprüfung der veröffentlichten
Sammlung hat bestanden: **62 PDFs, 5.721 Seiten, 62.343 lokale und
41.033 externe Verweise**. Darin sind die gegenseitigen Verknüpfungen beider
Lesefassungen und ihrer Beweisbände enthalten.
