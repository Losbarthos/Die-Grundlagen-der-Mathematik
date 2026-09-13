# B15–B27: unabhängige Schlusslisten

Lesende Prüfung abgeschlossen: 613 Haupttheoreme und 435 registrierte Hilfssätze, insgesamt 1048 aktive Aussagenanzeigen. Zwei noch unnummerierte Schlusslisten mit zusammen fünf Aussagen gefunden, beide in Band 21. Keine Quellen oder PDFs verändert; keine Builds und keine PDF-Erzeugung.

Alle Anzeigen wurden als vollständige Formeln inventarisiert und gelesen; zusätzlich wurden Kommas, \dsep, Zeilenumbrüche und größere Abstände als Suchsignale ausgewertet. Die 50 vorhandenen nummerierten Familien bleiben erhalten. 37 Aufrufe in expliziten \iffalse-Blöcken von Band 20 sind separat dokumentiert und ausgeschlossen. Die Zahl der Haupttheoreme stimmt in jedem Band mit dem fertigen Register überein. Klassische theorem/lemma/proposition/corollary/satz/formulaThm-Umgebungen kommen zusätzlich nicht vor.

| Band | Haupttheoreme | Registrierte Hilfssätze | Vorhandene Familien | Neue Kandidaten |
|---|---:|---:|---:|---:|
| B15 | 23 | 0 | 0 | 0 |
| B16 | 11 | 0 | 0 | 0 |
| B17 | 89 | 87 | 1 | 0 |
| B18 | 65 | 18 | 3 | 0 |
| B19 | 39 | 73 | 7 | 0 |
| B20 | 160 | 40 | 0 | 0 |
| B21 | 56 | 27 | 12 | 2 |
| B22 | 18 | 8 | 0 | 0 |
| B23 | 7 | 2 | 0 | 0 |
| B24 | 4 | 0 | 0 | 0 |
| B25 | 2 | 0 | 0 | 0 |
| B26 | 64 | 0 | 4 | 0 |
| B27 | 75 | 180 | 23 | 0 |

## Konkrete Kandidaten

### 21.5.5.1 – RealSequenceLinearLimitRules

Quelle: `Bd. 21 - Folgen.tex:2632`; Makro: `FormulaThmDeltaK`.

Drei eigenständige, durch Kommas und Zeilenumbrüche getrennte Grenzwertfolgerungen für Summe, Differenz und skalare Multiplikation. Keine römischen Teilkennzeichnungen vorhanden.

Bisherige Anzeige:

```tex
a,b\colon\mathbb N\to\mathbb R\dsep
  A,B,c\in\mathbb R\dsep
  a_n\to A\dsep b_n\to B
  \vdash
  \begin{aligned}[t]
  (a+b)_n&\to A+B,\\[-2pt]
  (a-b)_n&\to A-B,\\[-2pt]
  (ca)_n&\to cA
  \end{aligned}
```

Vorgeschlagene Anzeige:

```tex
\begin{aligned}[t]
  &a,b\colon\mathbb N\to\mathbb R\dsep A,B,c\in\mathbb R\dsep
    a_n\to A\dsep b_n\to B\vdash{}\\[-2pt]
  &\text{(i)}\quad(a+b)_n\to A+B,\\[-2pt]
  &\text{(ii)}\quad(a-b)_n\to A-B,\\[-2pt]
  &\text{(iii)}\quad(ca)_n\to cA.
\end{aligned}
```

FormulaThmDeltaK durch FormulaThmDeltaKR mit neuer Anzeige, exakt alter Originalanzeige als Strukturargument, gleicher ID und gleichen DeltaRows ersetzen. Gemeinsame bisherige Prämissen einmal voranstellen; keine Voraussetzung streichen. Die drei registrierten Beweisteile bleiben unverändert.

### 21.6.2.2(H2) – B21ReserveMarkerDistinct

Quelle: `Bd. 21 - Folgen.tex:3856`; Makro: `proofpartwideindR`.

Die registrierte Hilfsaussage enthält ohne vorausgehendes \vdash zwei durch \dsep (sichtbares Komma) getrennte Resultate: Typisierung der drei Marker und deren paarweise Verschiedenheit. Die Kommas innerhalb c_0,c_1,c_2 sind dagegen nur eine Variablenliste und bleiben zusammen.

Bisherige Anzeige:

```tex
c_0,c_1,c_2\in D\dsep c_0\neq c_1\land(c_0\neq c_2\land c_1\neq c_2)
```

Vorgeschlagene Anzeige:

```tex
\begin{aligned}[t]
  &\text{(i)}\quad c_0,c_1,c_2\in D,\\[-2pt]
  &\text{(ii)}\quad c_0\neq c_1\land(c_0\neq c_2\land c_1\neq c_2).
\end{aligned}
```

Nur erstes Anzeige-Argument von proofpartwideindR ändern. Das zweite R-Strukturargument und die optionale ID B21ReserveMarkerDistinct exakt erhalten. Hilfsnummer H2, Parent, Anker und vorhandene Beweisschrittfortsetzung ab 30 unverändert lassen.

## Abgrenzungen und Beispiel

Das genannte Theorem 27.2.3.4 (`WordConcatenationShiftedGraphSubset`, Band 27 Zeile 830) besitzt bereits korrekt die Punkte (i) und (ii) mit jeweils ihren unterschiedlichen Voraussetzungen. Es ist deshalb kein neuer Änderungsfall. Gleiches gilt für alle übrigen vorhandenen römischen Familien im Prüfbereich.

Ausdrückliche logische Konjunktionen bleiben in diesem Auftrag eine Aussage, etwa `IntAddZero`, `RealCutOrderCharacterization`, `DirectedNeighborhoodMembership`, `FinitePathInitialSegment` und `B27InnerAddressChildren`. Die Zeilen unter dem gemeinsamen Existenzquantor von `IntegerAdditionQuotientDescent` bilden eine gebundene Matrix; ihre Aufteilung in unabhängige Schlussaussagen würde die Bedeutung verändern. `IndexedFamilyReindexingImage` ist eine Gleichheits-/Inklusionskette. Die beiden übrigen Kommas in `c_0,c_1,c_2` sind eine Variablenliste. Keine dieser Stellen wird als zusätzliche unnummerierte Schlussfamilie vorgeschlagen.

Prüfbelege: `b15-b27-inventory.json` enthält alle 1048 Aussagen mit Quelle, registrierter Nummer/ID, kompletter Anzeige und abschließender Einzelklassifikation. `b15-b27-candidates.json` enthält die beiden konkreten Anzeigevorschläge einschließlich exakt erhaltbarer Original-Strukturargumente. `b15-b27-verification.json` dokumentiert Umfang, Registerabgleich und Quellhashes. `scan-b15-b27.py` erzeugt das strukturelle Inventar; `finalize-b15-b27-review.py` ergänzt die manuelle Schlusslistenprüfung.
