# Lesefassung und Beweistabellen für „Die Grundlagen der Mathematik“

Stand: 18. September 2026. Redaktioneller Vorschlag auf Grundlage des aktuellen Arbeitsstands. Dieses Dokument ergänzt das Projekt um eine Konzeption und einen ausformulierten Musterabschnitt; es stellt noch keine Umstellung der LaTeX-Ausgaben dar.

**Nachtrag:** Der Pilot zu Band 08 samt Anschluss an Band 11 und Navigation
in Band 00 wurde anschließend umgesetzt. Den aktuellen Stand, die Ausgaben
und Prüfungen dokumentiert der [Umsetzungsbericht](lesefassung-und-beweise-umsetzung-2026-09-18.md).
Die folgenden Aussagen zum noch nicht implementierten Stand beschreiben
den Zeitpunkt der ursprünglichen Konzeption.

**Empfehlung:** Die vorhandene Beweisbibliothek um eine zusammenhängende Lesefassung erweitern. Mit Cantor–Schröder–Bernstein in Band 08 beginnen, anschließend die Verbindung zur Gleichmächtigkeit in Band 11 erproben. Die bestehende Gesamtausgabe bleibt als vollständige Arbeits- und Referenzausgabe sinnvoll.

## 1. Der Chatverlauf, sinngemäß und verdichtet

Quelle: [„Mathematik systematisch schreiben“](https://chatgpt.com/share/6aad1458-de38-83eb-ad91-f3e27abae086), im Browser gelesen. Die folgenden sieben Punkte geben den Gesprächsgang zusammenfassend wieder, nicht wörtlich.

1. **Ausgangsfrage:** Wie kann eine vollständige Abhandlung ihre großen Entwicklungslinien sichtbar halten? **Vorschlag:** Dauerhafte Theorie, lokale Hilfskonstruktionen und Anschauung unterscheidbar darstellen.
2. **Skriptaufbau:** Größere Resultate erhalten eine Beweiseinheit aus Motivation, Konstruktion, Hilfssätzen, Beweis und abschließender Einordnung.
3. **Dateiaufteilung:** Ein zusammenhängendes Werk kann aus vielen Quelldateien entstehen. Dateigröße und mathematisches Gewicht sind verschiedene Dinge.
4. **Beweisebenen:** Prosabeweis, explizite Ableitung und maschinelle Prüfung erfüllen unterschiedliche Aufgaben. Die Übersetzung in den Kalkül muss nicht eindeutig sein.
5. **Cantor–Bernstein als Beispiel:** Eine rekursiv aufgebaute Teilmenge bestimmt, wo die eine Injektion vorwärts beziehungsweise die andere rückwärts verwendet wird.
6. **PDF-Aufteilung:** Der Haupttext enthält nachvollziehbare mathematische Beweise; ausführliche Ableitungstabellen können Begleitdateien bilden. Beweisstudien und Nachschlagehilfen ergänzen sie bei Bedarf.
7. **Dauerhafte Zuordnung:** Stabile Resultatkennungen verbinden Aussage, Beweis, Vertiefung und Abhängigkeiten über spätere Umgliederungen hinweg.

## 2. Meine Bewertung anhand des vorhandenen Projekts

Der Ansatz passt sehr gut zur Zielsetzung. Der wesentliche Gewinn wäre eine zusätzliche verständliche Argumentation zwischen Überblick und Tabellen. Eine reine Auslagerung vorhandener Tabellen würde diese Argumentation noch nicht schaffen.

Mehrere Voraussetzungen sind bereits vorhanden:

| Vorhandener Baustein | Bedeutung für die Weiterentwicklung |
| --- | --- |
| [main.tex](../main.tex) und einzeln baubare Fachbände | Einzel- und Gesamtausgabe werden schon aus gemeinsamen Quellen erzeugt. |
| [Band 00](<../Bd. 00 - Überblick über die Bände.tex>) und `tex/ueberblick/` | Eine Orientierungsschicht ist bereits angelegt. Sie kann um Lesepfade ergänzt werden. |
| `FormulaThmDeltaK`, `FormulaRefAuto` und das Formelregister | Benannte Resultate und ihre Verweise können für die Verknüpfung der Darstellungen weiterverwendet werden. |
| [BUILDING.md](../BUILDING.md) und die Auditwerkzeuge | Nummern, Register und PDF-Ziele werden bereits geprüft. Neue Ausgabearten müssen in diese Prüfungen integriert werden. |
| Cantor–Bernstein in [Band 08](<../Bd. 08 - Bijektive Funktionen.tex>) | Motivation, kleinste abgeschlossene Teilmenge und tabellarische Herleitung existieren bereits. Der Abschnitt eignet sich für einen begrenzten Pilotversuch. |

**Die entscheidenden Präzisierungen gegenüber dem Chat:**

- **Mehrere Darstellungstiefen sind keine automatisch unterschiedlichen logischen Metaebenen.** Motivation und Prosabeweis können dieselbe mathematische Aussage behandeln. Echte Metatheorie untersucht etwa Syntax, Ableitbarkeit und Modelle; dafür enthält Band 48 bereits eigene Bausteine.
- **Eine formal aussehende Tabelle ist noch kein geprüfter Beweis.** Entscheidend sind ein präziser Kalkül, zulässige Definitionen, korrekte Regelanwendungen und ihre Nebenbedingungen. Der erfolgreiche Dokumentbau bescheinigt diese Eigenschaften nicht.
- **Bereits bewiesene Sätze dürfen weiter als Bausteine verwendet werden.** Explizite Ableitungen müssen die Anwendung und ihre Voraussetzungen belegen; sie müssen nicht bei jeder Verwendung die gesamte Vorgeschichte bis zu den Axiomen erneut abdrucken.
- **Die Existenz irgendeines formalen Beweises genügt nicht, um einen bestimmten Prosabeweis zu bestätigen.** Für eine belegte Entsprechung müssen seine tragenden Schritte, Voraussetzungen und Zwischenbehauptungen tatsächlich durch die zugeordnete Ableitung gedeckt sein. Eine eindeutige Übersetzung ist dabei unnötig.
- **Lesbarkeit gilt auch für die Beweistabellen.** Aussage, Kontext, Beweisabschnitte und Verweise bleiben dort nötig. Besonders kurze Tabellen können in der Lesefassung stehenbleiben, wenn sie die Argumentation am besten erklären. In Band 01 sind Tabellen selbst Lehrgegenstand.
- **Der Umfang der Darstellung sollte dem Satz entsprechen.** Ein elementares Lemma benötigt keine sieben redaktionellen Ebenen. Eine anspruchsvolle Konstruktion profitiert dagegen von einer ausdrücklich erklärten Strategie.
- **Die Seitenzahlen im Chat sind hypothetisch.** Daraus lässt sich keine belastbare Umfangs- oder Aufwandsschätzung für dieses Manuskript ableiten.

## 3. Welche Ausgaben ich für dieses Projekt vorsehen würde

| Ausgabe | Inhalt und Aufgabe | Vorgehen |
| --- | --- | --- |
| **Band 00: Überblick** | Leitfragen, zentrale Begriffe und Resultate, Voraussetzungen und empfohlene Lesepfade | Vorhandenen Band gezielt ergänzen. |
| **Lesefassung eines Fachbands** | Definitionen, Axiome, Beispiele, Sätze und nachvollziehbare Prosabeweise einschließlich erforderlicher Hilfskonstruktionen | Zunächst nur für das Pilotpaket erarbeiten. |
| **Beweistabellen eines Fachbands** | Zugehörige Aussagen und Voraussetzungen, Lemmon-Ableitungen, interne Hilfsresultate und Rückverweise zur Lesefassung | Erst als Ausgabe einführen, wenn die Verknüpfung zuverlässig funktioniert. |
| **Integrierte Gesamtausgabe** | Lesetext und explizite Ableitungen zusammen | Als Arbeits-, Archiv- und Referenzausgabe weiterführen. |
| **Einzelne Beweisstudien** | Alternative Ansätze, Entdeckung, größere Beispiele und zusätzliche Anschauung | Nur bei erkennbarem Mehrwert erstellen. |

Ein zusätzliches umfassendes Referenz-PDF würde ich zunächst zurückstellen: Band 00 und die vorhandenen Register decken bereits einen Teil dieses Bedarfs ab.

Ein mathematisch vollständiger Prosabeweis darf auf vorher bewiesene Sätze verweisen. Er muss weder deren Beweise wiederholen noch jeden logischen Mikroschritt ausschreiben. Er muss jedoch die Voraussetzungen des verwendeten Satzes erfüllen und den entscheidenden Übergang erkennbar begründen. „Siehe Beweisdatei“ ersetzt diesen Übergang nicht.

Ein einzelner Fachband bleibt auf seine ausgewiesenen Vorgänger angewiesen. Selbständige Lesbarkeit bedeutet hier: Die Argumentation des Abschnitts ist mit diesen Grundlagen nachvollziehbar; sämtliche früheren Bände müssen nicht im selben PDF wiederholt werden.

## 4. Konkrete Projektfassung am Satz von Cantor–Schröder–Bernstein

### Einordnung im vorhandenen Werk

Die Platzierung im Chat ist nur exemplarisch. Im aktuellen Projekt steht der funktionale Satz in **Band 08**, unter der ID `CantorBernsteinFixedInjections`. **Band 11** überträgt ihn unter `CantorSchroederBernstein` in die Sprache der Gleichmächtigkeit und des kardinalen Vergleichs. Diese Reihenfolge ist sachlich sinnvoll.

Die im Chat verwendete Konstruktion über natürliche Zahlen und Rekursion eignet sich hier nicht als Ersatz: Band 08 liegt vor Band 10. Die vorhandene Konstruktion über die kleinste abgeschlossene Teilmenge benötigt diesen späteren Aufbau nicht. Auch das Auswahlaxiom wird für den folgenden Beweis nicht benötigt.

Der Quelltext enthält bereits eine ausführliche Motivation mit vorwärts und rückwärts verwendeten Pfeilen. Diese kann in die Lesefassung übernommen und mit dem nachstehenden Prosabeweis verbunden werden. Die Zeichen `S`, `C`, `D` und die Familie `K` sind im folgenden Text lokale Abkürzungen. Insbesondere ist `C` die bereits vorhandene Cantor–Bernstein-Teilmenge zu `F` und `G`.

### Muster für die Lesefassung

**Satz.** Seien `A` und `B` Mengen und

\[
F:A\longrightarrow B,\qquad G:B\longrightarrow A
\]

injektiv. Dann existiert eine Bijektion von `A` nach `B`.

**Beweisidee.** Wir suchen eine Teilmenge `C` von `A`, auf der wir `F` verwenden. Auf dem verbleibenden Teil soll die Umkehrung einer geeigneten Einschränkung von `G` verwendet werden. Dazu müssen die beiden Zweige disjunkte Bildbereiche besitzen, die zusammen `B` ergeben.

**Die benötigte Teilmenge.** Setze

\[
S:=A\setminus G[B],\qquad
\mathcal K:=\{X\subseteq A\mid S\subseteq X\ \land\ G[F[X]]\subseteq X\},
\qquad C:=\bigcap\mathcal K.
\]

Die Familie `K` ist durch Aussonderung aus der Potenzmenge von `A` eine Menge. Sie ist nicht leer: Wegen `F[A]` als Teilmenge von `B` und `G[B]` als Teilmenge von `A` gehört `A` selbst zu `K`. Daher ist ihr Durchschnitt definiert und eine Teilmenge von `A`. Diese Definition von `C` stimmt mit der im Manuskript verwendeten Formulierung überein, wonach ein Element von `A` in jeder geeigneten Teilmenge liegen muss.

Jedes Mitglied von `K` enthält `S`, also gilt `S` als Teilmenge von `C`. Außerdem ist `C` unter dem Doppelschritt abgeschlossen: Ist `x` in `C`, so liegt `x` in jedem `X` aus `K`; deshalb liegt `G(F(x))` in jedem solchen `X` und somit in `C`. Also gilt

\[
G[F[C]]\subseteq C.
\]

Damit gehört `C` selbst zu `K` und ist dessen kleinstes Mitglied.

**Die entscheidende Gleichung.** Es gilt

\[
C=S\cup G[F[C]].
\]

Zum Beweis setze `D:=S ∪ G[F[C]]`. Aus den gerade bewiesenen Eigenschaften folgt `D ⊆ C`. Bilder erhalten Inklusionen, also

\[
G[F[D]]\subseteq G[F[C]]\subseteq D.
\]

Ferner ist `S ⊆ D ⊆ A`. Somit gehört `D` zu `K`. Die Minimalität von `C` liefert `C ⊆ D`; zusammen mit der umgekehrten Inklusion ergibt dies die behauptete Gleichung.

**Der zweite Bildbereich.** Aus der Gleichung folgt

\[
A\setminus C=G[B]\setminus G[F[C]].
\]

Denn ein Element von `A` liegt genau dann außerhalb von `C`, wenn es weder in `A \ G[B]` noch in `G[F[C]]` liegt, also genau dann, wenn es in `G[B]`, aber nicht in `G[F[C]]` liegt. Wegen `F[C] ⊆ B` und der Injektivität von `G` gilt außerdem

\[
G[B]\setminus G[F[C]]=G[B\setminus F[C]].
\]

Für diese letzte Gleichheit ist die Injektivität wesentlich: Ein Element `b` außerhalb von `F[C]` kann nicht dasselbe Bild unter `G` haben wie ein Element von `F[C]`; umgekehrt kann ein Urbild eines Punkts aus `G[B] \ G[F[C]]` nicht zu `F[C]` gehören.

**Zusammensetzen der Bijektion.** Eine Injektion ist auf jeder Teilmenge ihres Definitionsbereichs bijektiv auf ihr Bild. Daher sind

\[
F|_C:C\longrightarrow F[C]
\quad\text{und}\quad
G|_{B\setminus F[C]}:B\setminus F[C]\longrightarrow A\setminus C
\]

Bijektionen. Bezeichne die Umkehrfunktion der zweiten Bijektion mit `J` und definiere

\[
H(a):=
\begin{cases}
F(a),&a\in C,\\
J(a),&a\in A\setminus C.
\end{cases}
\]

Die Definitionsbereiche der Zweige sind disjunkt und vereinigen sich zu `A`; damit ist `H` eine wohldefinierte Funktion von `A` nach `B`. Jeder Zweig ist injektiv. Zwischen den Zweigen können keine gleichen Werte auftreten, denn ihre Bildbereiche sind `F[C]` und `B \ F[C]`. Also ist `H` injektiv. Jeder Punkt von `B` gehört zu genau einem dieser beiden Bildbereiche und wird vom zugehörigen bijektiven Zweig getroffen. Also ist `H` auch surjektiv und damit die gesuchte Bijektion. □

**Einordnung.** Die Teilmenge `C` organisiert diesen Beweis. Als dauerhaft nutzbares Hauptergebnis steht anschließend die Existenz einer Bijektion aus zwei gegebenen Injektionen zur Verfügung. Die allgemeine Bilddifferenzregel, die Einschränkung auf das Bild und das Verkleben von Bijektionen behalten unabhängig davon ihren eigenen Wert als wiederverwendbare Sätze. Die Konstruktion funktioniert auch bei leeren Mengen.

### Zuordnung zu den vorhandenen Ableitungen

Der Mustertext verdichtet den vorhandenen Beweisweg. Die folgende Zuordnung zeigt seine tragenden Schritte; sie ist kein maschinelles Zertifikat einer Übereinstimmung sämtlicher Prosasätze mit Tabellenzeilen.

| Schritt der Lesefassung | Vorhandene IDs |
| --- | --- |
| Definition und Lage von `C` | `CantorBernsteinPartDef`, `CantorBernsteinPartSubset` |
| Startbereich, Minimalität, Abgeschlossenheit | `CantorBernsteinPartContainsSeed`, `CantorBernsteinPartMinimal`, `CantorBernsteinPartClosed` |
| Gleichung für `C` | `CantorBernsteinPartFixedPoint` |
| Komplement und zweiter Bildbereich | `CantorBernsteinComplementIdentity`, `CantorBernsteinSecondBranchImage` |
| Allgemeine Bilddifferenzregel | `InjectiveImageDifference` in Band 06 |
| Einschränkung, Umkehrung und Verkleben | `InjectionRestrictionToImageBijective`, `InverseFunctionBijection`, `CaseFunBijectiveDisjointTargets` |
| Abschließender Satz | `CantorBernsteinFixedInjections` |

Die Schreibweise `G⁻¹` für eine überall auf `A` definierte Umkehrfunktion wäre hier voreilig: `G` ist zunächst lediglich injektiv. Die explizite Einschränkung im Mustertext folgt der vorhandenen Projektnotation.

Eine spätere Beweisstudie könnte den Durchschnittsbeweis mit der rekursiven Konstruktion vergleichen. Dafür wären die natürlichen Zahlen und die benötigte Rekursion als Voraussetzungen auszuweisen und die Gleichheit beider Konstruktionen zu beweisen. Die graphische Deutung kann dort ebenfalls ausführlicher werden.

## 5. Redaktionelle Regeln für die weitere Umsetzung

**Drei unabhängige Angaben statt einer einzigen Einteilung.** Für jedes wichtige Resultat würde ich festhalten:

1. **Mathematische Art:** Definition, Axiom, Satz, Vermutung oder Beispiel.
2. **Rolle im Text:** Leitresultat, allgemein verwendetes Hilfsresultat oder Hilfe innerhalb eines bestimmten Beweises.
3. **Nachweisstand:** Prosabeweis vorhanden, Tabelle vorhanden, manuelle Prüfung mit Umfang und Datum, gegebenenfalls maschinelle Prüfung mit Prüfer und Version.

Diese Angaben haben unterschiedliche Bedeutungen. Ein Hilfssatz kann vollkommen bewiesen sein; ein zentraler Satz kann noch eine offene Voraussetzung besitzen. Ein später ergänztes Maschinenprüfmerkmal darf nicht aus einem erfolgreichen LaTeX-Audit abgeleitet werden.

„Lokal“ wäre zunächst eine redaktionelle Rolle, keine Änderung der logischen Gültigkeit oder der Sichtbarkeit einer Satz-ID. Vor dem Verbergen oder Entfernen eines Hilfsresultats sind seine Verwendungen zu prüfen. Allgemeine Hilfsmittel wie Einschränkung und Verkleben bleiben an ihrem bisherigen sachlichen Ort.

Für größere Resultate empfiehlt sich eine erkennbare Folge: Fragestellung, präzise Aussage, Beweisstrategie, erforderliche Konstruktion, Beweis und anschließende Verwendung. Für kurze Resultate genügen Aussage und Beweis. Zusätzliche Absatztypen wie `beweisidee`, `beweiskonstruktion` und `einordnung` sollten keine konkurrierenden Satznummern erzeugen.

## 6. Technische Umsetzung ohne doppelte Pflege

Die mathematische Aussage samt Voraussetzungen soll nur einmal gepflegt werden. Lesebeweis und Tabelle sind zwei zugeordnete Darstellungen. Eine mögliche spätere Quellaufteilung für den Pilot ist:

```text
tex/b08/cantor-bernstein/
    aussagen.tex
    lesetext.tex
    beweistabellen.tex
```

Diese Dateien sind ein Strukturvorschlag und wurden noch nicht angelegt. Die vorhandenen Banddateien und `main.tex` bleiben die Einstiegspunkte; es besteht kein Anlass, alle 48 Bände umzubenennen oder neu zu nummerieren.

Die bestehenden semantischen IDs sollten weiterverwendet werden. Beispielsweise bleibt `CantorBernsteinFixedInjections` dieselbe Identität, unabhängig von Drucknummer, PDF-Dateiname oder Seite. Für ältere, ausschließlich über Formeltexte adressierte Aussagen können bei tatsächlichem Bedarf zusätzliche benannte IDs ergänzt werden.

**Die wesentliche technische Schwierigkeit liegt beim Ausblenden.** `FormulaThmDeltaK` verbindet Satzdarstellung, Zähler, Label und Registrierung. Wenn eine Lesefassung ganze Hilfssatzblöcke überspringt, können sich nachfolgende Nummern verschieben und Sprungziele fehlen. Ein bloßer Schalter um `tabproof` löst außerdem weder die fehlenden Prosabeweise noch die Behandlung interner Hilfsresultate.

Deshalb würde ich zunächst alle Satzdeklarationen und Nummern beibehalten und ausschließlich die Beweisdarstellung variieren. Erst anschließend wäre eine kompaktere Auswahl von Hilfssätzen möglich, gestützt auf eine gemeinsame kanonische Nummernzuordnung. Unterschiedliche Ausgaben benötigen getrennte Build- und Registerverzeichnisse sowie eine eindeutige Zuordnung von Resultat-ID, Ausgabe und PDF-Ziel.

Dies umfasst auch die innerhalb der Beweisumgebungen registrierten Hilfsresultate mit H-Nummern. Die Makros in `tex/impl/proof-tables.tex` vergeben dafür eigene Labels und Registereinträge. Ihre Identitäten müssen auch bei ausgeblendeter Tabelle erhalten bleiben; Verweise müssen zu einem vorhandenen Ziel in der Lesefassung oder im zugehörigen Beweis-PDF führen. Nur die Hauptsatzdeklarationen beizubehalten genügt nicht.

Zwischen Lesetext und Beweistabelle sollten Hin- und Rücklinks entstehen. Der Beweisband muss die zugehörige Aussage und ihre Voraussetzungen anzeigen. Bei bandübergreifenden Links entscheidet die Ausgabezuordnung, welches PDF und welches Ziel gemeint sind; der Dateiname darf nicht aus einer Satznummer erraten werden.

Die Datei `band-dependencies.tsv` beschreibt die Build- und Importordnung. Ein zusätzlicher Graph tatsächlich verwendeter Sätze muss diese Ebene ausdrücklich von mathematischen Voraussetzungen unterscheiden. Verweise lassen sich als Kandidaten erfassen; sie bilden ohne weitere Prüfung keine vollständige semantische Abhängigkeitsanalyse.

## 7. Reihenfolge und überprüfbare Meilensteine

1. **Begrenzter Pilot in Band 08.** Den vorhandenen Cantor–Bernstein-Abschnitt in Aussage, Erklärung und Tabellen gliedern. Den Mustertext gegen die tatsächlich verwendeten Definitionen und Beweisabschnitte redaktionell prüfen. Zunächst kann dies innerhalb der bestehenden integrierten Ausgabe geschehen.
2. **Zwei Darstellungen desselben Pilotpakets.** Lesefassung und Beweistabellen mit gemeinsamen Aussagen, identischen IDs und stabilen Nummern bauen. Auch die integrierte Darstellung muss weiter funktionieren. Ausgeblendete Inhalte dürfen keine versehentlichen fehlenden Voraussetzungen erzeugen.
3. **Die Verwendung in Band 11 einbeziehen.** Der dortige Gleichmächtigkeitssatz soll den vorhandenen funktionalen Satz nutzen. Damit werden echte bandübergreifende Verweise erprobt. Band 00 erhält die entsprechenden Zugänge.
4. **Gezielte Kontrolle.** Aussagen und Voraussetzungen vergleichen; Prosabeweis und Tabelle mathematisch abgleichen; Nummern und Links in Einzel- und Gesamtausgabe prüfen; betroffene PDF-Seiten ansehen. Die Abnahme umfasst sowohl Mathematik als auch Dokumenttechnik.
5. **Erst danach auf Band 27 übertragen.** Wörter, Bäume, Induktion und Rekursion bieten einen anspruchsvollen zweiten Fall. Die Darstellung muss dabei jeweils deutlich zwischen Strukturaxiomen, konkretem Modell und daraus hergeleiteten Sätzen unterscheiden.
6. **Maschinenprüfung als eigenes Teilprojekt.** Mit einem kleinen Ausschnitt des Kalküls beginnen. Benötigt werden unter anderem eine eindeutige Formelsyntax, Annahmenverwaltung, kollisionsfreie Substitution ohne Variablenfang und Prüfung der Nebenbedingungen von Quantorenregeln. Nicht unterstützte Regeln oder Definitionen müssen als ungeprüft kenntlich bleiben.

Eine maschinelle Prüfung der Tabellen wäre langfristig wertvoll. Die bessere Lesefassung ist davon unabhängig erreichbar und sollte nicht auf die Fertigstellung eines allgemeinen Beweisprüfers warten.

## 8. Grundlage und Grenzen dieser Ausarbeitung

Geprüft wurden der geteilte Chat, Projektbeschreibungen, der Aufbau von `main.tex`, die Registeranbindung, der aktuelle Cantor–Bernstein-Abschnitt, die betreffenden Überblicks- und Folgesätze sowie ausgewählte Projektberichte. Eine ergänzende unabhängige Sichtung betraf die Gesamtstruktur und die mathematische Kernkonstruktion des Musterbeweises.

Dies ist keine erneute Korrektheitsprüfung aller 48 Fachbände. Es wurden keine LaTeX-Ausgabeprofile implementiert und keine neuen PDFs erzeugt. Die konkrete Lieferung dieses Schritts besteht in der auf das Projekt abgestimmten Konzeption und dem vollständigen Prosabeispiel.
