# Auslagerung des Dedekindschen Rekursionssatzes

Stand: 19. September 2026.

## Ergebnis und Aufteilung

Band 10 enthält den unveränderten Dedekindschen Rekursionssatz unter der
neuen Nummer **10.4.3.1**, eine kurze Einordnung sowie Links zu zwei
eigenständigen Ergänzungen. Die Schnittkonstruktion, ihre technischen
Hilfsaussagen und der vollständige Beweis sind ausgelagert.

- Band 10: **198 statt 222 PDF-Seiten**.
- Gesamtband: **2.788 statt 2.811 PDF-Seiten**.
- Lesefassung: **5 PDF-Seiten**, einschließlich Titelblatt. Vollständiger
  Prosabeweis über admissible Mengen, Rekursionskern, Fixierungsmengen,
  gemeinsame Induktion über eindeutige Existenz sowie Funktionalität und
  Eindeutigkeit. Keine lokalen nummerierten Deklarationen.
- Beweistabellen: **27 PDF-Seiten**, einschließlich Titelblatt. Die
  Ergänzung besitzt ihre eigenen Nummern mit dem Präfix **10E**.

Die PDFs liegen nach demselben Muster wie die bisherigen Ergänzungen unter
`output/04 Zahlen und Folgen/Ergänzungen/Dedekindscher Rekursionssatz/`.
Der Fachband bleibt unmittelbar im übergeordneten Themenordner.

Anders als beim Mogiljanskaja-Gegenbeispiel wird die Rekursionsabbildung
im weiteren Fachband ständig verwendet. Deshalb bleiben ihre Definition,
Eigenschaften und Anwendungen im Hauptwerk. `RecFunDef` benennt jetzt
mittels Iota die durch den Hauptsatz eindeutig bestimmte Funktion.
Die Definition benötigt den Rekursionskern nicht mehr. Die drei
grundlegenden Eigenschaften werden unmittelbar aus dieser Definition
gewonnen. Auch die spätere Fassung des Rekursionssatzes mit `n+1` nutzt
für ihre Eindeutigkeit den öffentlichen Hauptsatz.

Die Beweisergänzung zeigt nach dem Hauptbeweis ausdrücklich, dass der
konstruierte Kern mit dieser benannten Rekursionsabbildung übereinstimmt.
Der Überblick erläutert die neue Aufteilung und verweist auf beide Fassungen.

## Quellen und Erstellung

- `tex/b10/dedekind/construction.tex`: ausgelagerte Konstruktion und
  unveränderte Beweistabellen.
- `tex/b10/dedekind/reading.tex`: eigenständiger erklärender Beweis.
- `editions/b10-dedekind-{reading,proofs}.tex`: getrennte Dokumente.
- `tex/impl/dedekind-editions.tex`: gemeinsame PDF-Verweise.
- `scripts/dedekind-editions.py`: aktuelle Registerimporte, unabhängige
  Nummerierung und Prüfungen der Verweise.
- `scripts/build-dedekind-editions.ps1`: Aufbau der Ergänzungen und der
  betroffenen Fachbände; Einbindung in Gesamtbuild und Publisher.

Die Referenzziele des Rekursionssatzes und der Rekursionsabbildung liegen
weiterhin in Band 10. Die Beweistabellen besitzen 44 eigene Ziele:
3 Axiome des Hilfsbegriffs, 4 Definitionen, 19 Hilfssätze und 18 registrierte
Teilaussagen. Der Hauptsatz wird dort nicht erneut registriert.

## Prüfungen

- Die Hauptsatzdeklaration stimmt vollständig mit dem bisherigen Text
  überein. Die neue Iota-Definition und ihre drei Grundableitungen wurden
  unabhängig mathematisch geprüft.
- Die aktive Beweislinie bleibt unverändert: **20 Tabellen mit 347
  Beweiszeilen**. Zusätzlich wurde das bereits deaktivierte Archivmaterial
  mit 5 Tabellen und 91 Zeilen unverändert übertragen. Die Tabellenblöcke
  stimmen zeichengetreu mit der Sicherung überein.
- Der Hauptband enthält keine Abhängigkeiten mehr von Rekursionskern,
  Admissibilität oder den privaten Hilfssätzen. Der Beweis verwendet keine
  später eingeführte Addition oder Ordnung und kein Auswahlprinzip.
- Registerprüfung der Ergänzungen bestanden: 44 lokale Verweisziele in den
  Beweistabellen, keine in der Lesefassung, getrennte Zuständigkeiten und
  vollständige aktuelle Importe. Beide Ergänzungen sind von der Hauptsatzseite
  aus verlinkt; der Schlussbeweis ist zusätzlich direkt erreichbar.
- Der Vergleich der Register bestätigt: Alle 50 ausgelagerten Datensätze
  bleiben bis auf das Nummernpräfix unverändert. Im Hauptband ändern sich
  nach der vorgesehenen Umnummerierung ausschließlich die Formel der
  Definition `RecFunDef` und die dafür angepassten Ableitungen.
- Alle 5 Seiten der Lesefassung und alle 27 Seiten der Beweistabellen wurden
  gerendert und visuell geprüft. Kritische Satzköpfe, Teilbeweisüberschriften
  und Schlussseiten wurden zusätzlich einzeln kontrolliert. Auch die
  geänderten Seiten in Band 10, der Überblick und die Hauptsatzseiten
  763–764 des Gesamtbands sind geprüft.
- Eingehende PDF-Verweise wurden im gesamten veröffentlichten Bestand
  untersucht. Wegen geänderter Band-10-Ziele wurden neben B00 die Bände
  B15, B16, B17, B19, B20, B21, B22, B26, B27, B28, B29, B33, B34, B35,
  B37, B38, B39, B43, B47 und B48 sowie die Mogiljanskaja-Ergänzungen
  neu erzeugt. Alle kanonischen Nummern und PDF-Ziele dieser 20 Folgebände
  stimmen mit der Sicherung überein; daraus entstehen keine zusätzlichen
  Neubauabhängigkeiten.
- Die Referenzprüfung aller 22 neu gebauten Fach- und Überblicksbände
  ist bestanden. Das Quelleninventar erfasst auch die ausgelagerten
  Dateien und meldet keine ungültigen Steuerzeichen.
- Der Gesamtband wurde vollständig neu gesetzt. Seine Referenzprüfung
  ist bestanden; sämtliche Registereinträge und Satznummern stimmen
  mit den 49 Einzelbänden überein.
- 26 Einzelband- und Begleit-PDFs wurden im Ausgabeordner aktualisiert.
  Die anschließende Prüfung aller 55 dortigen Einzelbände und Ergänzungen
  ist bestanden: 13.753 interne und 38.727 dokumentübergreifende Links.
- Auch der Gesamtband ist im Ausgabeordner aktualisiert. Die abschließende
  Prüfung des vollständigen Bestands ist bestanden: **56 PDFs mit 5.680
  Seiten, 65.510 internen und 38.752 dokumentübergreifenden Links**.
  Insgesamt wurden 27 unterschiedliche PDFs aktualisiert oder neu angelegt.

Die Register- und Linkprüfungen sichern Dokumentintegrität und Navigation;
sie ersetzen keine maschinelle Prüfung der mathematischen Schlüsse.
