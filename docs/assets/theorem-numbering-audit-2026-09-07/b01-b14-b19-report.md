# Sichtbare Nummern für Theoremfamilien – Band 01–14 und 19

## Umfang und Auswahl

1.475 Haupttheoreme in den 15 aktiven Bandquellen geprüft. Die breite Kandidatensuche erfasste 392 mehrzeilige bzw. Komma-/Trennzeichen-Aussagen. Keine klassischen `theorem`, `lemma`, `satz`, `corollary` oder `proposition`-Umgebungen vorhanden. Archive wurden nicht verändert.

Neun echte bisher unnummerierte Familien erhielten insgesamt 34 sichtbare Teilnummern. Bestehende Familiennummern sowie einzelne Konjunktionen, Gleichheits-/Äquivalenzketten, Prämissenlisten, Tupel und Quantorvariablenlisten wurden beibehalten. In Band 01–04, 06–09 sowie 11–14 waren keine weiteren unnummerierten Haupttheoremfamilien zu ergänzen.

## Geänderte Familien

- **Bd. 05 - Funktionen.tex:3063 – Vereinigung einer kompatiblen Familie von
Funktionsgraphen** (`CompatibleFunctionGraphFamilyUnion`): 2 Teilnummern, eine Schlussaussage je Zeile. Ausgangszeile 3063.
- **Bd. 10 - Natürliche Zahlen.tex:16114 – Strenge Monotonie und Injektivität der Zweierpotenzfunktion** (`PeanoPowerTwoStrictMonotoneInjective`): 2 Teilnummern, eine Schlussaussage je Zeile. Ausgangszeile 16114.
- **Bd. 19 - Reelle Zahlen.tex:2044 – Gesetze der reellen Addition** (`RealCutAdditiveLaws`): 4 Teilnummern, eine Schlussaussage je Zeile. Ausgangszeile 2044.
- **Bd. 19 - Reelle Zahlen.tex:2271 – Negation kehrt die Schnittordnung um** (`RealCutNegationOrder`): 4 Teilnummern, eine Schlussaussage je Zeile. Ausgangszeile 2263.
- **Bd. 19 - Reelle Zahlen.tex:2544 – Abgeschlossenheit der multiplikativen Schnittoperationen** (`RealCutMultiplicativeClosure`): 4 Teilnummern, eine Schlussaussage je Zeile. Ausgangszeile 2528.
- **Bd. 19 - Reelle Zahlen.tex:3384 – Gesetze der reellen Multiplikation** (`RealCutMultiplicativeLaws`): 5 Teilnummern, eine Schlussaussage je Zeile. Ausgangszeile 3356.
- **Bd. 19 - Reelle Zahlen.tex:4516 – Die rationale Einbettung erhält die Körperoperationen** (`RationalToRealEmbeddingArithmetic`): 4 Teilnummern, eine Schlussaussage je Zeile. Ausgangszeile 4479.
- **Bd. 19 - Reelle Zahlen.tex:4778 – Grundgesetze des reellen Betrags** (`RealAbsoluteValueLaws`): 5 Teilnummern, eine Schlussaussage je Zeile. Ausgangszeile 4733.
- **Bd. 19 - Reelle Zahlen.tex:4955 – Grundgesetze des reellen Abstands** (`RealDistanceLaws`): 4 Teilnummern, eine Schlussaussage je Zeile. Ausgangszeile 4901.

Bei `RealCutMultiplicativeClosure` behält jede der vier Aussagen ihre eigenen Voraussetzungen; die bereits innerhalb der zweiten Aussage stehende Konjunktion bleibt eine Aussage. Bei `PeanoPowerTwoStrictMonotoneInjective` steht die punktweise Monotonie mit ihren Voraussetzungen unter (i), die selbstständige Injektivitätsaussage unter (ii).

## Referenz- und Strukturtreue

Alle neun bisherigen `FormulaThmDeltaK`-Aufrufe wurden auf die zentral bereitgestellte Variante `FormulaThmDeltaKR` umgestellt. Diese erhält die ursprüngliche vollständige Strukturformel bytegetreu als eigenes Argument sowie die unveränderte ID und den Delta-Kontext. Automatisch registrierte Theoreme ohne expliziten Key mussten in diesem Bestand nicht verändert werden.

Der balancierte Parser hat alle neun Original-Strukturargumente und Anzeigen gegen das Änderungsinventar geprüft. Sämtliche Beweistabellenzeilen in allen 15 Dateien sind gegenüber den Ausgangskopien identisch. Keine Theorem-, Beweisschritt- oder Hilfsteilzähler geändert. Keine Builds/PDF-Änderungen durch diesen Agenten.

## Zusätzliche beauftragte QA-Korrekturen in Band 08

- Direkt unter `TranspositionBijectionExists`: die sichtbaren Zeichenkodierungsfehler in „Abkürzung“ und „eingeführten“ korrigiert.
- `TranspositionTermValues`, Anzeige des Hilfssatzes „Werte der Fallabbildung“: die zu breite Formel auf Voraussetzung und zwei Schlusszeilen verteilt. Das separate Keyformel-Argument ist unverändert.

Die Ausgangskopie von Band 08 wurde unmittelbar nach diesen beiden lokalen QA-Korrekturen erstellt; ihre exakt bekannten vorherigen Fragmente wurden für den gemeinsamen Diff wiederhergestellt. Alle anderen Ausgangskopien stammen direkt vom Zeitpunkt vor der Nummerierung.

## Dateien

- `b01-b14-b19-before/`: Ausgangskopien
- `b01-b14-b19-candidates.json`: vollständige breite Kandidatenliste
- `b01-b14-b19-changes.json`: detailliertes Inventar einschließlich Original-Strukturformeln und neuen Anzeigen
- `b01-b14-b19-checks.json`: Prüfung von Schlüsseln und unveränderten Beweiszeilen
- `b01-b14-b19-changes.patch`: isolierter Diff dieser Aufgabe
