# Unabhängige Prüfung der 29 neuen B28-Theoremfamilien

Alle 29 Einträge aus `b28-changes.json` mit den aktuellen `FormulaThmDeltaKR`-Anzeigen in beiden B28-Dateien sowie den vor der Nummerierung gespeicherten Strukturformeln verglichen.

## Ergebnis

- Alle 29 Original-Strukturformeln sind exakt erhalten; die IDs blieben unverändert.
- Sämtliche sichtbaren Teilnummern entsprechen den im Ledger vorgesehenen Gruppen.
- Voraussetzungen wurden nicht verloren oder zwischen Aussagen vertauscht. Insbesondere bleiben die zwei unterschiedlichen Prämissenblöcke bei `SemigroupIsoDirectProducts` erkennbar erhalten.
- Kommata in Tupeln, in Mengen- und Variablenlisten sowie in den Parametern `K∈{L,R,J}` und `S=Sub,LId,RId,Id` wurden nicht als zusätzliche Schlussaussagen aufgetrennt.
- Gleichheitsketten und die gemeinsame Halbgruppenkonjunktion bei `MogiljanskajaArgumentM2Semigroups` bleiben jeweils eine Aussage.
- Die mit `coloneqq` angeschlossenen Vorschriften bei Quotienten- und Konjugationsabbildung definieren den gerade beschriebenen Funktionsterm; sie bleiben in derselben nummerierten Aussage.
- Keine verbliebenen versehentlich verklebten `vdash`-Befehle in den Anzeigen.

## Ausschließlich an Anzeigen vorgenommene Layoutkorrekturen

Sechs Anzeigen erhielten Fortsetzungszeilen, damit die neue Teilnummer nicht zusätzlich zu langen Ketten oder Parameterlisten in einer Zeile Platz finden muss:

1. `MogiljanskajaArgumentM1WellDefined`: Gleichheitskette von (i) umgebrochen.
2. `MogiljanskajaArgumentM6ProductClassification`: Voraussetzungen von (i)/(ii) über der langen Zugehörigkeitsäquivalenz.
3. `MogiljanskajaArgumentM14ProductPartsInvariant`: Voraussetzung von (iii) über der Produktgleichheitskette.
4. `SemigroupIsoPrincipalIdealsAndGreen`: Parameterliste der Green-Relationen als Fortsetzung von (iii).
5. `SemigroupIsoEndomorphismConjugation`: Definitionsvorschrift `C_f(u)` als Fortsetzung von (i).
6. `SemigroupIsoSubstructureOrders`: Liste der vier Unterstrukturarten als Fortsetzung von (i).

Für jede Änderung wurde die aktuelle gemeinsame Datei unmittelbar vor der Mutation eingelesen. Geändert wurde ausschließlich das erste Argument des jeweiligen KR-Aufrufs. Beweistabellenzeilen wurden unmittelbar davor/danach verglichen und sind bei dieser Mutation identisch. Strukturargumente und IDs sind unverändert. Das Detailinventar steht in `b28-independent-layout-changes.json`.

## Vollständigkeit Band 00

Band 00 und sämtliche über `tex/ueberblick/` eingebundenen Quellen geprüft. Sie enthalten keine Theoremdeklarationen, sondern Übersichtstabellen und Verweise auf die Fachbände; hier ist keine Theoremfamilie zu nummerieren.

Die Prüfung ist eine Quellenprüfung. Der Vollbuild und die anschließende PDF-Sichtkontrolle erfolgen getrennt.
