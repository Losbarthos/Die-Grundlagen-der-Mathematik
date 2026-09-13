# B29–B44: unabhängige Schlusslisten

## Ergebnis

**Keine verbleibende unabhängige kommagetrennte Schlussliste gefunden.** Vollständig geprüft wurden 560 registrierte Aussagen: 455 Haupttheoreme und 105 Hilfssätze. Alle 317 breit gefilterten Interpunktions-/Mehrzeilenkandidaten sowie die übrigen 243 Anzeigen wurden einzeln gelesen. Keine Quellenänderung, kein Build und keine PDF-Erzeugung.

Der frische Scan umfasst alle aktiven Banddateien 29 bis 44. Es gibt in diesem Bereich keine theorem-/lemma-/proposition-/corollary-Umgebungen, keine eingebundenen Teildateien und keine sonstigen direkten Theoremregistrierungen. Erfasst sind 446 `FormulaThmDeltaK`, 9 `FormulaThmDelta`, 104 `proofpartwideindR` und 1 `proofpartpairedindR`. Alle 105 Hilfssätze besitzen eine explizite ID. Die Quellhashes nach Abschluss stimmen mit dem Scanbeginn überein.

Die frühere Prüfung erfasste die 455 Haupttheoreme. Diese neue Prüfung schließt zusätzlich sämtliche 105 registrierten Hilfssätze ein. Die insgesamt bereits nummerierten 58 Familien anderer Bereiche werden dadurch nicht verändert; in B29–B44 liegt keine solche römisch nummerierte Schlussfamilie vor.

## Abdeckung

| Band | Haupttheoreme | Registrierte Hilfssätze | Verbliebene Schlusslisten |
| --- | ---: | ---: | ---: |
| 29 | 4 | 0 | 0 |
| 30 | 1 | 0 | 0 |
| 31 | 5 | 2 | 0 |
| 32 | 1 | 0 | 0 |
| 33 | 3 | 0 | 0 |
| 34 | 2 | 0 | 0 |
| 35 | 5 | 0 | 0 |
| 36 | 2 | 0 | 0 |
| 37 | 36 | 5 | 0 |
| 38 | 40 | 7 | 0 |
| 39 | 37 | 7 | 0 |
| 40 | 83 | 43 | 0 |
| 41 | 5 | 1 | 0 |
| 42 | 68 | 6 | 0 |
| 43 | 119 | 34 | 0 |
| 44 | 44 | 0 | 0 |

## Abgrenzung anhand konkreter Anzeigen

| Quelle / ID | Tatsächliche Form | Entscheidung |
| --- | --- | --- |
| B37:660 `FiniteSemigroupIndexPeriodUniqueness` | μ=μ′ ∧ λ=λ′ | Explizite Konjunktion, keine Kommaliste |
| B37:785 `FiniteSemigroupMonogenicSize` | Trägerbeschreibung ∧ Endlichkeit ∧ Mächtigkeit | Eine explizit konjunktive Aussage |
| B37:1284 `FiniteSemigroupRelabellingAction` | Fünf mit ∧ verknüpfte Wirkungseigenschaften | Keine unabhängige Kommaliste |
| B38:1854 `SemigroupIsoBetweenMonoidsIdentityAndUnits` | F(e)=u ∧ ∀a (Einheitenäquivalenz) | Eine Konjunktion mit Quantorbereich |
| B39:399 `NaturalSemiringMonoidStructures` | Additive Struktur ∧ multiplikative Struktur | Eine explizite Konjunktion |
| B40:2275 `GroupCompletionOperationQuotientDescent` | ∃!u ∃p,q,r,s (drei Repräsentantengleichungen mit ∧) | Quantor-Variablenliste und gebundene Konjunktion |
| B40:3394 `GroupCompletionClassInverse` | Rechte Inversengleichung ∧ linke Inversengleichung | Eine explizite Konjunktion |
| B40:3611 `GroupCompletionEmbeddingTheorem` | Gruppenstruktur ∧ Homomorphie ∧ Injektivität | Eine explizite Konjunktion |
| B40:5760 `IntegerRingMapConstants` | Nullwert ∧ Einheitswert | Eine explizite Konjunktion |
| B42:2874 `FiniteZeroJoinSemilatticePairInfima` | ∃m (untere Schranke ∧ Größtheitsbedingung ∧ Infimum) | Ein gebundener Aussagekomplex |
| B43:4735 `FranklComplementPairSupremumBounds` | Trägerzugehörigkeit ∧ erste Schranke ∧ zweite Schranke | Eine explizite Konjunktion |
| B44:878 `MetricIdentityConstantContinuous` | Stetigkeit der Identität ∧ Stetigkeit der Konstanten | Eine explizite Konjunktion |
| B44:1053 `MetricIsometryPreservesStructure` | Stetigkeit ∧ ∀Folge (Cauchy-Implikation) | Eine explizite Konjunktion |

## Separater redaktioneller Hinweis

`Bd. 42 - Halbverbände und Verbände.tex:3176`, registrierter Hilfssatz `MinimalSeparatorDecomposition`: Die Anzeige enthält zwei `\vdash`. Zwischen beiden stehen `u,v\in A` und `u\JoinOp{}v=j` als zusätzliche Voraussetzungen. Die einzige Konklusion lautet `u=j\lor v=j`. Hier liegt keine aufteilbare Schlussliste vor. Vermutlich ist der erste Turnstile durch einen Prämissentrenner zu ersetzen. Root wurde informiert; diese Lesekontrolle hat die Quelle nicht verändert.

## Nachweise

- `b29-b44-inventory.json`: Vollständiges unverändertes Scaninventar, Anzeigeformel, Strukturkey, ID, Titel, Quelle, Zeile, übergeordneter Satz und Ausgangshashes.
- `b29-b44-candidates.txt`: Vollständiger Wortlaut aller 317 breit gefilterten Kandidaten.
- `b29-b44-reviewed.json`: Entscheidung und Begründung für alle 560 Anzeigen, leere tatsächliche Nummerierungskandidatenliste, separate redaktionelle Beobachtung, bestätigte Quellhashes.
- `scan-b29-b44.py` und `review-b29-b44.py`: Reproduzierbare Inventar- und Berichtsaufbereitung; keine Manuskriptedits.
