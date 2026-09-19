# Mengenungleichheit durch einen Zeugen in der rechten Menge

Prüfung vom 16. September 2026.

## Neuer Satz und Beweis

Direkt nach Theorem 3.4.2.2 steht jetzt **Theorem 3.4.2.3**:

> Aus x ∈ B und x ∉ A folgt A ≠ B.

Theorem 3.4.2.2 liefert mit vertauschten Mengen B ≠ A. Die bereits bewiesene
Symmetrie der Ungleichheit (2.9.3.1) ergibt A ≠ B. Beide Schlusszeilen hängen
von beiden Voraussetzungen ab. Der Beweis hat vier nummerierte Zeilen.

In 3.4.2.2 wurden außerdem die Abhängigkeiten der beiden Schlusszeilen auf 1,2
berichtigt und die zweite Disjunktionseinführung eingesetzt: Der hergeleitete
Existenzsatz ist die rechte Alternative der Ungleichheitscharakterisierung.

## Ergebnis der Anwendungssuche

Der neue Satz wird an **14 Stellen in 11 bestehenden Haupttheoremen** verwendet.
Die folgende Liste unterscheidet tatsächliche Kürzungen von notwendigen
Begründungskorrekturen. Insgesamt entfallen **14 nummerierte Beweiszeilen** sowie
**zwei weitere geschachtelte Regelanwendungen**. Die vier Zeilen des neu
hinzugefügten Theorems sind dabei nicht gegengerechnet.

`H1` usw. bezeichnet registrierte Hilfstheoreme innerhalb des jeweils genannten
Haupttheorems. Alle bisherigen Resultatnummern bleiben erhalten.

| Theorem / Teiltheorem | Inhalt | Änderung |
|---|---|---|
| 19.2.2.1(H1) | Nichtleerheit und Echtheit der Hauptschnitte | Richtung des Satzverweises und erforderliche Annahmeabhängigkeiten berichtigt |
| 19.3.1.4(H3) | Strikte Hinrichtung der Ordnungserhaltung durch Hauptschnitte | Richtung des Satzverweises und erforderliche Annahmeabhängigkeiten berichtigt |
| 19.4.1.1(H1) | Summe zweier Schnitte | Richtung des Satzverweises und erforderliche Annahmeabhängigkeiten berichtigt |
| 19.4.1.1(H2) | Negation eines Schnittes | Richtung des Satzverweises und erforderliche Annahmeabhängigkeiten berichtigt |
| 19.4.2.1(H4) | Positives Produkt ist ein Schnitt | 88 → 87 Beweiszeilen |
| 19.4.2.1(H5) | Positives Reziprokes ist ein Schnitt | 82 → 81 Beweiszeilen |
| 19.6.1 | Archimedische Eigenschaft der reellen Zahlen | Fehlende Ungleichheitsbegründung ergänzt |
| 19.6.3 | Dichtheit der rationalen Zahlen in den reellen Zahlen | Fehlende Ungleichheitsbegründung ergänzt (zwei Stellen) |
| 20.3.7.38 | Frische Adjunktion endlicher Teilmengen | 18 → 17 Beweiszeilen |
| 20.6.2.8 | Die Nichtnullzahlen bilden eine echte Teilmenge | 8 → 5 Beweiszeilen |
| 21.6.4.3 | Tatsächliche Bildmenge der Verschiebungsfolge | Zwei geschachtelte Regeln entfallen; Zeilenzahl unverändert |
| 27.3.1.2 (ii) | Trennung der Konstruktoren | 24 → 19 Beweiszeilen |
| 27.4.1.2 | Die beiden Adresskinder sind verschieden | 14 → 11 Beweiszeilen |

Die beiden Mengenzeugen in Band 27 sind das Wurzelvorkommen `(0,(1,|S|))`
im Knotencode und das neue Endvorkommen `(|p|,1)` im rechten Adresskind.
Die vorhandenen Wortdefinitionen und Adjunktionssätze liefern jeweils die
Mitgliedschaft in der rechten Menge und die Nichtmitgliedschaft in der linken.

In Band 19 wurden die lokalen Existenzannahmen der betroffenen Schlussketten
vollständig bis zu ihrer Entladung ausgewiesen. Beim additiven Schnitt wurde
die zuvor fehlende Entladung der äußeren Schranken ergänzt. Dies sind
Begründungskorrekturen, keine zusätzlich gezählten Kürzungen.

## Vollständiger Prüfumfang

Untersucht wurden alle 48 aktiven Fachbände sowie der Überblick B00 und ihre
rekursiv eingebundenen Quelldateien. Das Ausgangsmanuskript enthält 3.057 aktive
`proof`-/`tabproof*`-Umgebungen; mit dem neuen Satz sind es 3.058.
Geteilte Umgebungen enthalten zusätzliche innere Teilbeweise. Band 01 stellt
die logischen Schlussregeln bereit und verwendet diese Umgebungen nicht.

Die Prüfung erfasst insbesondere Mengenungleichheit, echte Inklusion,
Element-/Nichtelementzeugen, Gleichheitswidersprüche, Symmetrieschritte und
Verweise auf den bisherigen Ungleichheitssatz. Die vollständigen
Kandidatenbeweise einschließlich der Fließtextbeweise wurden geprüft.
Kommentare, deaktivierte und verschachtelte `iffalse`-Alttexte, `Archive/`
sowie nicht eingebundene historische Prüfkopien sind ausgeschlossen.

| Band | Vorhandene aktive Beweisumgebungen | Ergebnis |
|---|---:|---|
| 00 | 0 | Überblick ohne eigene Beweise |
| 01 | 0 | Logische Grundlagen; keine Rückabhängigkeit von Band 03 |
| 02 | 273 | Keine weitere Kürzung durch den neuen Satz |
| 03 | 321 | Neuer Satz und Korrektur von 3.4.2.2 |
| 04 | 10 | Keine weitere Kürzung durch den neuen Satz |
| 05 | 134 | Keine weitere Kürzung durch den neuen Satz |
| 06 | 38 | Keine weitere Kürzung durch den neuen Satz |
| 07 | 76 | Keine weitere Kürzung durch den neuen Satz |
| 08 | 98 | Keine weitere Kürzung durch den neuen Satz |
| 09 | 25 | Keine weitere Kürzung durch den neuen Satz |
| 10 | 327 | Keine weitere Kürzung durch den neuen Satz |
| 11 | 63 | Keine weitere Kürzung durch den neuen Satz |
| 12 | 10 | Keine weitere Kürzung durch den neuen Satz |
| 13 | 28 | Keine weitere Kürzung durch den neuen Satz |
| 14 | 17 | Keine weitere Kürzung durch den neuen Satz |
| 15 | 25 | Keine weitere Kürzung durch den neuen Satz |
| 16 | 11 | Keine weitere Kürzung durch den neuen Satz |
| 17 | 94 | Keine weitere Kürzung durch den neuen Satz |
| 18 | 68 | Keine weitere Kürzung durch den neuen Satz |
| 19 | 41 | Anwendungen siehe oben |
| 20 | 167 | Anwendungen siehe oben |
| 21 | 66 | Anwendungen siehe oben |
| 22 | 18 | Keine weitere Kürzung durch den neuen Satz |
| 23 | 7 | Keine weitere Kürzung durch den neuen Satz |
| 24 | 4 | Keine weitere Kürzung durch den neuen Satz |
| 25 | 2 | Keine weitere Kürzung durch den neuen Satz |
| 26 | 77 | Keine weitere Kürzung durch den neuen Satz |
| 27 | 245 | Anwendungen siehe oben |
| 28 | 200 | Keine weitere Kürzung durch den neuen Satz |
| 29 | 4 | Keine weitere Kürzung durch den neuen Satz |
| 30 | 1 | Keine weitere Kürzung durch den neuen Satz |
| 31 | 9 | Keine weitere Kürzung durch den neuen Satz |
| 32 | 1 | Keine weitere Kürzung durch den neuen Satz |
| 33 | 3 | Keine weitere Kürzung durch den neuen Satz |
| 34 | 2 | Keine weitere Kürzung durch den neuen Satz |
| 35 | 5 | Keine weitere Kürzung durch den neuen Satz |
| 36 | 2 | Keine weitere Kürzung durch den neuen Satz |
| 37 | 38 | Keine weitere Kürzung durch den neuen Satz |
| 38 | 41 | Keine weitere Kürzung durch den neuen Satz |
| 39 | 38 | Keine weitere Kürzung durch den neuen Satz |
| 40 | 38 | Keine weitere Kürzung durch den neuen Satz |
| 41 | 30 | Keine weitere Kürzung durch den neuen Satz |
| 42 | 5 | Keine weitere Kürzung durch den neuen Satz |
| 43 | 34 | Keine weitere Kürzung durch den neuen Satz |
| 44 | 1 | Keine weitere Kürzung durch den neuen Satz |
| 45 | 68 | Keine weitere Kürzung durch den neuen Satz |
| 46 | 122 | Keine weitere Kürzung durch den neuen Satz |
| 47 | 44 | Keine weitere Kürzung durch den neuen Satz |
| 48 | 126 | Keine weitere Kürzung durch den neuen Satz |

## Geprüfte Anwendungen ohne Vorteil

- **20.6.3.4, Jeder Funktionswert verfehlt die Diagonalmenge:** Eine
  Fallunterscheidung mit beiden Mengenungleichheitssätzen wäre möglich.
  Sie spart nur eine Tabellenzeile, benötigt aber eine zusätzliche Schlussregel
  und stärkere Verschachtelung. Der ursprüngliche Beweis bleibt unverändert.
- **CantorNoRealSurjection in Band 20:** Der knappe Fließtext schließt bereits
  unmittelbar aus einem reellen Wert außerhalb des Bildes auf die Ungleichheit.
  Ein zusätzlicher Satzverweis verkürzt oder repariert diesen Beweis nicht.
- **B48CohenReals:** Die Unterscheidung der generischen Teilmengen durch ein
  abweichendes Bit ist bereits Bestandteil einer einzelnen Beweiszeile.
  Ein neuer Verweis erspart keinen Schritt der Dichtheits-/Generizitätsargumente.
- Ungleichheiten zweier Elemente anhand ihrer Zugehörigkeit zu derselben Menge
  verwenden eine andere Schlussform. Sie sind keine Instanzen des neuen Satzes.
- Bereits verfügbare Nichtleerheit, Zahl- oder Funktionswertungleichheit,
  Nichtinklusion sowie zu beweisende Nichtelementbeziehungen wurden nur dann als
  Treffer gewertet, wenn die neue Mengenregel tatsächlich benötigte Schritte
  ersetzen oder eine fehlende Begründung ergänzen konnte.

## Validierung

Die Änderungen in Band 03, Band 19–21 und Band 27 wurden unabhängig anhand
der verwendeten Sätze, der Instantiierungen, der lokalen Annahmen und der
Zeilenzitate gegengeprüft. Die Prüfung bezieht sich auf die angefragte
Vereinfachung; sie ist keine allgemeine Korrektheitszertifizierung aller Beweise.

- Die fünf geänderten Einzelbände wurden erfolgreich neu gebaut. Die
  Verweisprüfung aller 49 Einzelbände einschließlich B00 ist bestanden.
- Der Gesamtband wurde nach drei LaTeX-Durchläufen mit 2.840 Seiten erfolgreich
  gebaut und hat seine abschließende Verweisprüfung bestanden. Die
  Theoremnummern der Einzelbände und des Gesamtbands stimmen überein; es gibt
  keine ungeklärten oder mehrdeutigen Satzverweise.
- Die Register von B19, B20, B21 und B27 sind gegenüber dem Ausgang unverändert.
  In B03 ist ausschließlich der neue Eintrag 3.4.2.3 hinzugekommen.
- Alle Seiten mit dem neuen Satz oder seinen Anwendungen wurden in den
  geänderten Einzelbänden und im Gesamtband gerendert und visuell geprüft;
  erforderliche Nachbarseiten wurden einbezogen. Im Gesamtband waren dies
  14 Zielseiten und sechs ergänzende Seiten. Es wurden keine durch die
  Änderungen verursachten Layoutmängel festgestellt. Bestehende globale
  Layoutwarnungen sind unverändert.

- Die PDFs der Bände 03, 19, 20, 21 und 27 sowie der Gesamtband wurden nach
  `output/` veröffentlicht. Ihre Seitenzahlen, Seitengeometrien und dekodierten
  Seiteninhalte stimmen vollständig mit den visuell geprüften Build-Dateien
  überein.
- Die abschließende Linkprüfung aller 50 veröffentlichten PDFs ist bestanden:
  5.708 Seiten, 66.382 lokale Links und 38.644 externe Links mit gültigen Zielen.
- `git diff --check` meldet keine Fehler in den Änderungen.
