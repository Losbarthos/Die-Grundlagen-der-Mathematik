# Cantor–Schröder–Bernstein: frühere Einordnung und kürzere Folgebeweise

Stand: 16. September 2026.

Der vollständige Beweis steht jetzt in **Band 08 „Bijektive Funktionen“**. Band 11 formuliert daraus die Charakterisierung der Gleichmächtigkeit durch gegenseitige Injektionen. Die Prüfung der Folgebände hat drei vorhandene Beweise verkürzt; bei zwei weiteren Anwendungen wurden Verweise und ein Codierungsdetail präzisiert. Aussagen über bestimmte Abbildungen, Isomorphismen und ihre Zusatzgesetze bleiben erhalten.

## Neue Einordnung

In [Band 08](<../Bd. 08 - Bijektive Funktionen.tex>) steht der konstruktive Kern als Satz **8.3.7.8**, `CantorBernsteinFixedInjections`:

> Aus einer Injektion von A nach B und einer Injektion von B nach A folgt die Existenz einer Bijektion zwischen A und B.

Der Abschnitt folgt auf die Konstruktionen zum Verkleben disjunkter Bijektionen. Er enthält die vollständige Argumentation: Definition der kleinsten geeigneten Cantor–Bernstein-Teilmenge, Startbereich, Minimalität, Abgeschlossenheit, Fixpunktgleichung, Komplementidentität und schließlich die beiden disjunkten bijektiven Zweige. Der erste Zweig verwendet die gegebene Injektion, der zweite die Umkehrung einer passenden Einschränkung der Gegeninjektion. Natürliche Zahlen, Rekursion, Endlichkeit und das Auswahlaxiom werden für diese Herleitung nicht benötigt.

Zwei Hilfssätze stehen dort, wo ihre Voraussetzungen erstmals vollständig vorliegen:

- [Band 06](<../Bd. 06 - Injektive Funktionen.tex>), **6.2.2.6**, `InjectiveImageDifference`: Injektionen erhalten die Differenz geeigneter Teilmengen unter der Bildbildung.
- [Band 08](<../Bd. 08 - Bijektive Funktionen.tex>), **8.3.2.4**, `InjectionRestrictionToImageBijective`: Die Einschränkung einer Injektion ist eine Bijektion auf ihr Bild.

In [Band 11](<../Bd. 11 - Äquivalenzrelationen.tex>) folgen auf die Grundlagen der Gleichmächtigkeit die Definitionen des kardinalen Vergleichs und seine elementaren Regeln. Satz **11.3.2.7**, `CantorSchroederBernstein`, übersetzt den funktionalen Satz in diese Sprache. Satz **11.3.2.8**, `EqCardMutualCardLeqEquiv`, hält beide Richtungen fest: Zwei Mengen sind genau dann gleichmächtig, wenn sie sich gegenseitig injektiv abbilden lassen. [Band 20](<../Bd. 20 - Endliche Mengen.tex>) verweist bei seinen Anwendungen auf diese früheren Ergebnisse.

## Verkürzte Beweise und gemeinsame Beweiskette

Die folgende Zählung erfasst Tabellenzeilen der Beweise, also `proofstep`-Aufrufe einschließlich Annahmen und Schlusszeilen. Sie misst weder Druckseiten noch bloße TeX-Quellzeilen.

| Band und bestehender Satz | Satz-ID | Vorher → nachher |
| --- | --- | ---: |
| [20.6.3.7: Die Potenzmenge der natürlichen Zahlen ist überabzählbar](<../Bd. 20 - Endliche Mengen.tex>) | `PowerSetNaturalsUncountable` | **10 → 2** |
| [20.6.3.13: Die reellen Zahlen sind überabzählbar](<../Bd. 20 - Endliche Mengen.tex>) | `RealsUncountable` | **11 → 2** |
| [48.3.2.2: Cantor–Schröder–Bernstein](<../tex/b48/03-transfinite-grundlagen.tex>) | `B48CSB` | **5 → 4** |

Die beiden Aussagen in Band 20 verwendeten denselben Widerspruch: Wäre die betreffende Menge höchstens abzählbar, ergäben die beiden Injektionsvergleiche mittels CSB Gleichmächtigkeit mit den natürlichen Zahlen. Das widerspricht dem bereits bewiesenen strikt größeren Umfang.

Dieses Argument steht nun einmal im neuen Hilfssatz **20.6.2.1**, `NaturalsStrictlyLessImpliesUncountable`: **Ist ℕ strikt weniger mächtig als A, so ist A überabzählbar.** Sein Beweis benötigt **10 Tabellenzeilen**. Die beiden Anwendungen bestehen anschließend jeweils aus dem vorhandenen strikten Vergleich und dem Hilfssatz. Einschließlich des neuen Beweises verkürzt sich die gesamte Kette damit von **21 auf 14 Tabellenzeilen**. Die Ersparnis beträgt sieben Zeilen; die ausgelagerte Arbeit ist vollständig mitgezählt. Die zugrunde liegenden Diagonalargumente bleiben bestehen.

In Band 48 entfällt die erneute rekursive Konstruktion der Cantor–Bernstein-Teilmenge. Die gewählten Injektionen werden auf den Satz aus Band 08 angewandt und das Ergebnis in die lokale Gleichmächtigkeitsnotation übersetzt. Die zugehörige Erläuterung stellt auch klar: Bei Anwendungen innerhalb eines Modells muss die Herleitung dort intern interpretiert werden; eine bloß außerhalb des Modells vorhandene Bijektion genügt nicht.

## Präzisierte Anwendungen in Band 48

Bei Satz **48.3.2.3**, `B48CardinalProduct`, in [den transfiniten Grundlagen](<../tex/b48/03-transfinite-grundlagen.tex>) verweisen die bestehenden CSB-Schlüsse jetzt ausdrücklich auf `B48CSB`. Die Codierung endlicher Tupel unterscheidet positive Längen und das leere Tupel: Ein nichtleeres Tupel erhält einen Code aus seinem Bild und seiner Länge; das leere Tupel erhält gesondert `(0,0)`. Damit wird die zusätzliche Einermenge bei Länge null ausdrücklich berücksichtigt.

Bei Satz **48.5.1.1**, `B48RealContinuum`, in [Band 48, Kontinuum](<../tex/b48/05-kontinuum.tex>) verweist der Schluss aus den beiden Injektionen ebenfalls ausdrücklich auf CSB. Die anschließende Kardinalgleichheit verweist auf die Potenzgesetze. **Diese beiden Beweise wurden nicht in ihrer Tabellenzeilenzahl verkürzt:** Es bleibt bei fünf beziehungsweise acht Zeilen.

## Geprüfte Bereiche ohne weitere Verkürzung

Die Suche umfasste die Hauptquellen der Bände 09–48 und die einschlägigen eingebundenen Unterdateien. Die relevanten Treffer wurden mit ihren Beweisen und Verwendungsketten geprüft. Das war eine gezielte Prüfung auf CSB-Verkürzungen, keine vollständige erneute Korrektheitsprüfung sämtlicher Inhalte.

Besonders geprüft wurden:

- **Faserbijektionen, Zahleneinbettungen und Folgenverschiebungen:** Die Aussagen betreffen fest definierte Abbildungen. Die Folgenverschiebung aus Band 10 wird in Band 21 ausdrücklich invertiert; ihre konkrete Bijektivität bleibt erforderlich.
- **Vollständige geordnete Körper:** In Band 19 bauen Schnittrekonstruktion, Addition, Multiplikation und Eindeutigkeit auf derselben Supremumsabbildung auf. Eine beliebige Mengenbijektion ersetzt diese Strukturgesetze nicht.
- **Folgen, Wege, Wörter und Bäume:** Indexverschiebungen, Endpunkte, Rekursionsgleichungen und eindeutige strukturtreue Rekursoren müssen erhalten bleiben.
- **Mogiljanskaja-Konstruktion, algebraische Rekonstruktion und Faserargumente:** Die Ketten in Band 21 und 28 benötigen festgelegte Reserveabbildungen und geschützte Teilbereiche. Die endlichen Potenzmengenargumente in Band 20, 31 und 42 lassen sich nicht durch eine unbegründete Kürzung von Potenzmengen ersetzen.
- **Quotienten und axiomatische Mengenlehre:** In Band 46 liegt die benötigte Quotientenbijektion bereits vor. Mostowski-Kollaps und Forcingargumente in Band 48 benötigen zusätzlich Strukturtreue, interne Graphen, Namenzählung oder Kardinalerhaltung.

## Kontrolle und Detailnachweise

**Inhaltliche Kontrolle, Neubau und PDF-Prüfung sind abgeschlossen.** Alle 19 verlagerten Hauptaussagen und ihre mathematischen Beweisschritte stimmen mit der gesicherten Ausgangsfassung überein; ihre IDs und Teilbeweise sind erhalten. Die Voraussetzungen und 142 Referenzaufrufe im verlagerten Material wurden geprüft, ohne einen neu entstandenen Vorwärtsverweis festzustellen. Lokale Umbruchhilfen halten die neu gesetzten Satzüberschriften und Beweisanfänge zusammen.

Die Einzelbände **B00 und B06–B48** wurden neu kompiliert; der vollständige Gesamtband wurde in drei LuaLaTeX-Läufen erstellt. `scripts/audit-build.ps1 -IncludeMain` hat sämtliche Einzelband- und Gesamtbandregister, Satznummern, importierten Ziele und Verweise erfolgreich geprüft. In den aktiven TeX-Quellen blieb auch kein ausgeschriebener Verweis auf die entfernten Nummern `20.6.1.*` zurück. Die betroffenen Beweisstellen und Überblicksseiten wurden als PNG gerendert und visuell kontrolliert.

Die geprüften PDFs stehen im Verzeichnis `output/`. Die abschließende Prüfung durch `scripts/publish-pdfs.py` erfasste **50 PDF-Dateien mit 5.714 Seiten, 66.427 internen Links und 38.687 externen PDF-Links**, ohne Fehler. Der Gesamtband umfasst **2.843 Seiten**. Bereits vorhandene Änderungen außerhalb dieses Auftrags wurden bewahrt.

Die vollständigen Kandidatenlisten, Messungen und Begründungen stehen in den Teilberichten für [Band 09–19](csb-audit-b09-b19-2026-09-16.md), [Band 20–27](csb-audit-b20-b27-2026-09-16.md) und [Band 28–48](csb-audit-b28-b48-2026-09-16.md).
