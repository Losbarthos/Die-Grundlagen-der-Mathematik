# B01–B14: Prüfung verbleibender Schlusslisten

Ergebnis: **keine weitere unnummerierte, kommagetrennte Familie unabhängiger Schlussaussagen gefunden.** Es sind keine Quellenänderungen vorzuschlagen.

Die Prüfung erfasst alle 14 aktiven Bandquellen. Der zunächst erfasste **Quellenrohbestand** enthält 1.436 Haupt- und 304 Hilfsdeklarationen, insgesamt 1.740 Anzeigeformeln. Darin sind 86 Haupt- und 31 Hilfsdeklarationen in drei ausdrücklich deaktivierten `\iffalse`-Blöcken von Band 10 enthalten. Der belastbare **aktive Umfang beträgt 1.350 Haupttheoreme und 273 registrierte Hilfssätze, insgesamt 1.623 Anzeigen**. Die aktive Labelmenge stimmt in jedem Band exakt mit dessen Registry überein. Die vollständige Aufschlüsselung steht in `b01-b14-active-coverage.md` und `.json`.

Der balancierte TeX-Parser erfasst auch Auto-, Delta-, R-/KR- und registrierte proofpart-Varianten. Es gibt in diesen Dateien keine klassischen theorem/formulaThm/lemma/corollary/proposition/satz-Umgebungen und keine ausgelagerten Band-Includes. Band 01 enthält keine Theoremdeklarationen dieses Typs; seine Regeln und Definitionen werden nicht zu Theoremen umklassifiziert.

Alle 338 durch Kommas, Trennzeichen, größere Abstände oder Formelumbrüche auffälligen, noch nicht nummerierten Anzeigen wurden inhaltlich gelesen; **313 davon sind aktiv**, 25 gehören zum ausgeschlossenen Rohbestand. Die acht schon nummerierten Familien sind sämtlich aktiv und wurden zusätzlich auf getrennte Aussagenzeilen und gemeinsame beziehungsweise unterschiedliche Voraussetzungen kontrolliert. In den übrigen Anzeigen fehlen die für eine solche Liste notwendigen Trennzeichen; ergänzende Suche nach Semikola und ausgeschriebenem „und“ ergab außerhalb der breiten Auswahl keine weiteren Fälle. Keine Parserfehler. Die Quellenhashes sind am Abschluss identisch mit dem Inventarbeginn.

Die folgende historische Tabelle zeigt den Quellenrohbestand; für aktive Endzählungen ist die Deckungstabelle in `b01-b14-active-coverage.md` maßgeblich.

| Band | Hauptdeklarationen roh | Hilfsdeklarationen roh | Breite Kandidaten gelesen, roh | Bestehende Familien kontrolliert | Neue Fälle |
|---|---:|---:|---:|---:|---:|
| 01 | 0 | 0 | 0 | 0 | 0 |
| 02 | 271 | 0 | 6 | 0 | 0 |
| 03 | 308 | 20 | 56 | 2 | 0 |
| 04 | 10 | 0 | 5 | 0 | 0 |
| 05 | 123 | 32 | 27 | 1 | 0 |
| 06 | 36 | 10 | 10 | 0 | 0 |
| 07 | 55 | 4 | 14 | 0 | 0 |
| 08 | 94 | 41 | 43 | 4 | 0 |
| 09 | 23 | 2 | 10 | 0 | 0 |
| 10 | 405 | 141 | 98 | 1 | 0 |
| 11 | 56 | 47 | 16 | 0 | 0 |
| 12 | 10 | 3 | 6 | 0 | 0 |
| 13 | 28 | 4 | 30 | 0 | 0 |
| 14 | 17 | 0 | 17 | 0 | 0 |

## Gezielte Abgrenzungen

Die vollständigen Anzeigen stehen im JSON-Inventar; diese Beispiele dokumentieren besonders naheliegende Fehlalarme.

- **2.9.1.8**, `Bd. 02 - Theoreme der Logik.tex:3651`, ID `BinaryFunctionRightArgumentCongruence`: Die Kommas stehen ausschließlich in den Argumentpaaren f(c,a) und f(c,b); behauptet wird eine Gleichheit.
- **CaseFunBijectiveBranchesCommonCodomain**, `Bd. 08 - Bijektive Funktionen.tex:2732`, ID `CaseFunBijectiveBranchesCommonCodomain`: Die beiden Funktionstypen bilden eine ausdrücklich mit land verbundene Schlussformel; kein selbstständiger Komma-Listeneintrag.
- **8.3.6.7**, `Bd. 08 - Bijektive Funktionen.tex:3187`, ID `CoreTransportValue`: Bereits (i) und (ii) in getrennten Zeilen; die zweite Aussage hat die zusätzliche Voraussetzung H in der Kernfamilie. Keine Umstellung erforderlich.
- **8.3.6.14**, `Bd. 08 - Bijektive Funktionen.tex:3878`, ID `LayerPowerMapValue`: Bereits (i) und (ii) in getrennten Zeilen; die zweite Aussage hat die zusätzliche Elementvoraussetzung X im Definitionsbereich. Die Voraussetzungen unterscheiden sich und bleiben bei den Punkten.
- **TranspositionTermValues**, `Bd. 08 - Bijektive Funktionen.tex:5141`, ID `TranspositionTermValues`: Die drei Teilbedingungen sind ausdrücklich mit zwei Konjunktionen verbunden. Der Zeilenumbruch vor dem letzten Allquantor trennt keine kommagetrennten Schlussaussagen.
- **9.4.1.1**, `Bd. 09 - Auswahlprinzip.tex:957`, ID `RetractionFiberBijection`: Eine einzige Existenzbehauptung über dieselbe Funktion f; die anschließenden Eigenschaften liegen gemeinsam in ihrer Quantormatrix.
- **RetractionFiberBijectionGluing**, `Bd. 09 - Auswahlprinzip.tex:1131`, ID `RetractionFiberBijectionGluing`: Auch im registrierten Hilfssatz ist es eine Existenzbehauptung mit einer verbundenen Matrix über denselben Zeugen, keine unabhängige Schlussliste.
- **10.4.3.9**, `Bd. 10 - Natürliche Zahlen.tex:5325`, ID `RecCoreLeastAdmissible`: Vier durch land verbundene Eigenschaften desselben Rekursionskerns sind eine Konjunktionsformel. Kein verbleibender unnummerierter Komma-Schluss.
- **10.4.3.13**, `Bd. 10 - Natürliche Zahlen.tex:5806`, ID `RecCoreStageBarrier`: Die zwei Implikationen sind ausdrücklich durch land verbunden und bleiben eine Schlussformel.
- **10.4.4.21**, `Bd. 10 - Natürliche Zahlen.tex:9262`, ID `PeanoRecursionStepAddOneIff`: Zwei Zeilen setzen eine einzelne Äquivalenz fort; keine zwei unabhängigen Folgerungen.
- **EqClassQuotientMembershipWitness**, `Bd. 11 - Äquivalenzrelationen.tex:1140`, ID `EqClassQuotientMembershipWitness`: Die Zeugenmatrix wird ausdrücklich als Konjunktion behauptet, nicht als unabhängige Kommaliste.
- **11.5.2.5**, `Bd. 11 - Äquivalenzrelationen.tex:1680`, ID `QuotProjImageToEqClass`: Eine Konjunktion aus Trägerzugehörigkeit und existenzieller Darstellung, keine kommagetrennte Liste.
- **14.2.2.5**, `Bd. 14 - Paarinfima und Paarsuprema.tex:425`, ID `PairSupremumAssociative`: Kommas gehören zu Operandenpaaren, Indexargumenten oder Voraussetzungen; der Schluss ist eine einzelne Assoziativitätsgleichheit.

## Bereits korrekte Familien

- `BooleanSetIntervalCoordinateCorrespondence`, `Bd. 03 - Mengenlehre.tex:5419`: vorhandene römische Nummern und einzelne Aussagezeilen beibehalten.
- `BooleanSetIntervalCoreEnvelope`, `Bd. 03 - Mengenlehre.tex:5563`: vorhandene römische Nummern und einzelne Aussagezeilen beibehalten.
- `CompatibleFunctionGraphFamilyUnion`, `Bd. 05 - Funktionen.tex:3063`: vorhandene römische Nummern und einzelne Aussagezeilen beibehalten.
- `CoreFamilyAdjoinedSplit`, `Bd. 08 - Bijektive Funktionen.tex:2949`: vorhandene römische Nummern und einzelne Aussagezeilen beibehalten.
- `CoreTransportValue`, `Bd. 08 - Bijektive Funktionen.tex:3187`: vorhandene römische Nummern und einzelne Aussagezeilen beibehalten.
- `ProtectedPowerSetExtension`, `Bd. 08 - Bijektive Funktionen.tex:3573`: vorhandene römische Nummern und einzelne Aussagezeilen beibehalten.
- `LayerPowerMapValue`, `Bd. 08 - Bijektive Funktionen.tex:3878`: vorhandene römische Nummern und einzelne Aussagezeilen beibehalten.
- `PeanoPowerTwoStrictMonotoneInjective`, `Bd. 10 - Natürliche Zahlen.tex:16113`: vorhandene römische Nummern und einzelne Aussagezeilen beibehalten.

Die Prämissen bei `CoreTransportValue`, `LayerPowerMapValue` und `PeanoPowerTwoStrictMonotoneInjective` unterscheiden sich zwischen den Punkten; sie stehen bereits bei den jeweiligen Aussagen. Bei den übrigen nummerierten Familien stehen die gemeinsamen Voraussetzungen vor dem Aussagenblock. Keine pauschale Umstellung der römischen Nummerierung.

## Belege und Grenzen

- `b01-b14-inventory.json`: alle 1.740 Rohdeklarationen mit Quelle, Zeile, ID oder Strukturformel, vollständiger Anzeige und Ausgangshash; `active` sowie getrennte aktive/deaktivierte Listen kennzeichnen die tatsächlich gesetzten 1.623 Anzeigen.
- `b01-b14-candidates.json` und `.txt`: die 338 breit ausgewählten, vollständig gelesenen Anzeigen.
- `b01-b14-review.json`: Status jeder Deklaration, bandweise Zählung, detaillierte Ausschlussbeispiele, leere Liste neuer Kandidaten.
- `scan-b01-b14.py` und `finish-b01-b14.py`: reproduzierbare Inventar- und Abschlussbelege; schreiben ausschließlich Prüfnotizen unter tmp.
- `classify-b01-b14-active.py`: anschließend anzuwendende aktive Deckungsprüfung; berücksichtigt auch ausschließlich über ID registrierte Hilfssätze und bestätigt die vollständigen Labelmengen.

Dies ist eine Prüfung der sichtbaren Theorem- und Hilfssatzaussagen auf Schlusslisten. Sie behauptet keine vollständige mathematische Prüfung oder Formalisierung aller Beweise. Keine Quelle, kein PDF und kein Build verändert oder erzeugt.
