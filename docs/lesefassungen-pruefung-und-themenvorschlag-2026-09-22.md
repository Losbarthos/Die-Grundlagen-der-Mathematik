# Nächste Lesefassung: Thema, Aufbau und Beweistabellen

Stand: 22. September 2026. Geprüft wurden die aktuellen Quellen einschließlich des vorhandenen, nicht eingecheckten Arbeitsstands.

**Empfehlung: „Wie aus einer Rechenregel eine Ordnung wird – Halbverbände zwischen Algebra und Ordnung“, zu Band 45.** Die Lesefassung soll die vollständige Entsprechung zwischen einer assoziativen, kommutativen, idempotenten Operation und einer partiellen Ordnung mit Suprema aller Elementpaare erklären. Dafür würde ich **19 Kerntabellen und vier Tabellen zum Vereinigungsbeispiel**, insgesamt **23 bestehende Beweistabellen**, in einen eigenen Ergänzungsband auslagern.

Die sechs vorhandenen Lesefassungen wurden in ihrem mathematischen Erzählgang vollständig gelesen. Die veröffentlichten PDFs wurden ergänzend auf Umfang und an je einer Inhaltsseite visuell abgeglichen. Dies ist keine vollständige Layout-, Link- oder zeilenweise Beweistabellenprüfung. Historische Zuschreibungen wurden nicht unabhängig recherchiert. In den sechs gelesenen Hauptargumenten wurde kein konkreter mathematischer Fehler festgestellt. Beim Vergleich möglicher Folgethemen wurden allerdings zwei präzisierungsbedürftige Hilfsaussagen in Band 19 gefunden; siehe unten.

Dieser Bericht dokumentiert die ursprüngliche Prüfung und den Vorschlag; für diese Prüfung wurden die mathematischen Quellen und bestehenden Ausgaben nicht geändert. Die anschließend beauftragte Umsetzung zu Band 45 ist im [Umsetzungsbericht](halbverbaende-und-ordnung-auslagerung-2026-09-22.md) beschrieben.

## 1. Inhaltliche Einschätzung der sechs bestehenden Lesefassungen

### Cantor–Schröder–Bernstein

Der Text hat einen geschlossenen Beweisgang: geeignete Zerlegung, kleinster abgeschlossener Teilbereich, Fixpunktgleichung, zwei Bijektionen und deren Zusammensetzen. Die Umkehrfunktion wird erst eingeführt, nachdem die eingeschränkte Abbildung nachweislich bijektiv ist. Der Anschluss an die Gleichmächtigkeit zeigt die Bedeutung des Satzes.

Straffen würde ich die zusätzliche Mengenidentität nach der bereits erreichten Komplementgleichung. Sie ist richtig, unterbricht aber den Übergang zu den beiden Bijektionen. Ein kleines Anwendungsbeispiel könnte die abstrakte Motivation ergänzen. Minimalität, Fixpunktgleichung und die disjunkten Bildbereiche müssen dagegen vollständig erklärt bleiben.

Quelle: [Lesebeweis](../tex/b08/cantor-bernstein/lesebeweis.tex), besonders Zeilen 67–150. Die zusätzliche Umformung steht ab Zeile 86. Veröffentlichter Umfang: 7 PDF-Seiten einschließlich Titelblatt.

### Dedekindscher Rekursionssatz

Diese Fassung ist zusammen mit der Klammerungsfassung die beste Aufbauvorlage: ein kleines wiederkehrendes Beispiel, genaue Voraussetzungen, eine erkennbare Schwierigkeit und ein darauf zugeschnittener Beweis. Besonders wichtig ist die Trennung zwischen einem eindeutigen Wert an jeder Stelle und der Eindeutigkeit der gesamten Funktion. Die Fixierungsmengen erklären, weshalb der kleinste abgeschlossene Graph tatsächlich ein Funktionsgraph ist.

Ergänzen würde ich eine kurze vollständig ausgeführte Anwendung: Für festes natürliches a liefern Anfangswert a und Nachfolger als Übergang die rekursive Definition der Addition. Der bestehende Schluss nennt diese Anwendung vor allem als Anschluss.

Quelle: [Lesetext](../tex/b10/dedekind/reading.tex), insbesondere Zeilen 201–262 und 328–366. Umfang: 9 PDF-Seiten.

### Ganze Zahlen

Die Fassung behandelt inzwischen weit mehr als die additive Differenzenkonstruktion: Quotient, Einbettung, Negation, Addition, Multiplikation, Normalformen, Ordnung, Diskretheit, zweiseitige Induktion und den Übergang zur Axiomatik. Gut ist die klare Unterscheidung zwischen den natürlichen Zahlen und ihrer eingebetteten Kopie. Die Konstruktion setzt nicht heimlich die erst zu gewinnende Subtraktion voraus.

Der Text ist mit 20 PDF-Seiten deutlich breiter als die übrigen. Ich würde die langen Ausrechnungen zur Multiplikationsassoziativität und Distributivität auf die entscheidenden Umformungen kürzen. Das Schrankenlemma als Vorbereitung der rationalen Zahlen passt besser in einen Ausblick. Wohldefiniertheit, Normalform und die beiden natürlichen Induktionen gehören weiterhin in den Hauptgang.

Quelle: [Lesetext](../tex/b17/integers/reading.tex), Einbettung ab Zeile 175, Multiplikationsrechnungen ab 480, Normalformen ab 608, Schrankenlemma ab 865. Die vollständigen Tabellen stehen bereits im eigenen Beweisband; hier geht es um die Gewichtung innerhalb der Prosa.

### Klammerungsunabhängigkeit

Der Aufbau ist besonders ausgewogen: fünf Klammerungen bei vier Faktoren, Gegenbeispiel Subtraktion, Trennung von Wort, Baum und Wert, Linksprodukt, Blockgesetz, Bauminduktion und Konsequenzen für die Schreibweise. Die zwei Induktionen haben erkennbare unterschiedliche Aufgaben. Nichtleerheit, Endlichkeit und unveränderte Reihenfolge werden sauber abgegrenzt.

Als Feinschliff genügt eine frühe Übersicht „Wort = Reihenfolge; Baum = Rechenplan; Auswertung = Ergebnis“. Der längere Begriffsabschnitt erhält dadurch Orientierung. Einen grundsätzlichen Umbau sehe ich nicht als nötig an.

Quelle: [Lesetext](../tex/b28/bracketing/reading.tex), Begriffsabschnitt ab Zeile 98, Blockgesetz ab 235, Baum-Normalform ab 327. Umfang: 11 PDF-Seiten.

### Mogiljanskaja-Gegenbeispiel

Die anspruchsvolle Konstruktion ist tatsächlich erklärt: Produktinformationen bestimmen, eine Reserve außerhalb der Produktrechtecke finden, eine konkrete Bijektion bauen und die Multiplikationserhaltung nachweisen. Der Schluss prüft beide nötigen Gleichheiten: Das Produkt der Bilder stimmt mit dem alten Produkt überein, und das alte Produkt wird von der Abbildung festgelassen.

Die größte Hürde ist die Zahl gleichzeitig benötigter Mengen und Abbildungen. Den langen Abschnitt „Konstruktion und Beweis“ würde ich in echte Teilabschnitte gliedern: Grundhalbgruppen, Produktinformationen, Reserve, Bijektion, Homomorphie. Dazu eine Übersicht der Abbildungen mit Definitionsbereich, Ziel und Aufgabe. Das späte Beispiel, bei dem eine Dreiermenge auf die neue Einermenge abgebildet wird, eignet sich als frühe Vorschau auf die Pointe.

Quelle: [Lesetext](../tex/b28/mogiljanskaja/reading.tex), Produktformel ab Zeile 135, Reserve ab 184, Bijektion ab 263, Homomorphie ab 445, Schlussbeispiel ab 568. Umfang: 11 PDF-Seiten.

### Formale Differenzen

Der allgemeine Einbettungssatz hat inzwischen eine eigenständige Ausrichtung: Rolle der Kürzbarkeit, Repräsentantenunabhängigkeit, Gruppenbildung und Einbettung. Das Beispiel mit zwei natürlichen Koordinaten, das Maximum-Gegenbeispiel und die notwendigen Bedingungen sind bereits vorhanden. Diese Ergänzungen dürfen nicht nochmals als fehlend vorgeschlagen werden.

Das Koordinatenbeispiel würde ich früher als Begleitbeispiel verwenden. So wird schneller deutlich, warum der Text über die ganzen Zahlen hinausführt. Die Überschneidung mit deren Lesefassung ist für unabhängige Lesbarkeit vertretbar; eine weitere Lesefassung mit lediglich derselben Quotientenidee hätte derzeit aber wenig zusätzlichen Nutzen.

Quelle: [Lesetext](../tex/b41/differences/reading.tex), Abgrenzung ab Zeile 31, Kürzbarkeitsstelle ab 134, Koordinatenbeispiel ab 404, Maximum und notwendige Bedingungen ab 480. Umfang: 11 PDF-Seiten.

## 2. Warum Band 45 als nächstes?

Die vorhandene Reihe erklärt bereits kleinste abgeschlossene Objekte, Rekursion, strukturelle Induktion, Quotienten und Einbettungen. Band 45 ergänzt einen anderen Gedanken: **Man kann dieselbe Struktur einmal durch eine Rechenoperation und einmal durch eine Ordnung beschreiben; beide Beschreibungen bestimmen einander.**

Der Einstieg benötigt nur Mengen, Vereinigung und einfache Rechenregeln. Das Ziel ist in einer Zeile verständlich:

\[
x\leq y\quad\Longleftrightarrow\quad x\vee y=y.
\]

Die Beweiskette ist im aktuellen Band vorhanden. Sie hat einen klaren Endpunkt, lässt sich mit einem einzigen kleinen Mengenbeispiel durchgehend veranschaulichen und öffnet den Zugang zum Ordnungszweig der Skripte. Die Voraussetzungen gelten auch ohne Endlichkeit, neutrales Element oder totale Vergleichbarkeit.

Als Umfang würde ich ungefähr 8–12 PDF-Seiten anstreben; dies ist ein redaktionelles Ziel, keine bereits ermittelte Satzlänge. Lesefassung und Beweisband würden als Ergänzungen zu Band 45 unter `output/05 Ordnungen und Verbände/Ergänzungen/Halbverbände und Ordnung/` stehen.

## 3. Vorgeschlagener Aufbau

1. **Eine Rechenregel verrät, was enthalten ist.** Mit den vier Teilmengen von `{a,b}` beginnen. Die Beobachtung `X vereinigt Y = Y` bedeutet genau `X ist Teilmenge von Y`. Kleine Vereinigungstafel und Hasse-Diagramm nebeneinanderstellen: zwei Darstellungen derselben Information.

2. **Welche Rechengesetze werden gebraucht?** Abgeschlossenheit, Assoziativität, Kommutativität und Idempotenz erklären. Die neue Relation durch `x ≤ y genau dann, wenn x ∨ y = y` definieren. Das Ziel früh vollständig nennen: Sie ist eine partielle Ordnung, und die Operation liefert jeweils das Paarsupremum.

3. **Aus den Rechengesetzen wird eine Ordnung.** Reflexivität, Antisymmetrie und Transitivität in kurzen vollständigen Rechnungen beweisen. Dabei sichtbar machen, wo welches Gesetz gebraucht wird. Im Mengenbeispiel sind `{a}` und `{b}` unvergleichbar: Eine partielle Ordnung muss keine totale Ordnung sein.

4. **Warum das Ergebnis die kleinste obere Schranke ist.** Zuerst `x ≤ x ∨ y` und `y ≤ x ∨ y`, danach die Minimalität gegenüber jeder gemeinsamen oberen Schranke. Hier genau zwischen einem Maximum der Zweiermenge und ihrem Supremum unterscheiden: `{a,b}` liegt über `{a}` und `{b}`, gehört aber nicht zur aus diesen beiden Mengen bestehenden Zweiermenge.

5. **Die Rückrichtung: Aus einer Ordnung wird eine Operation.** Eine partielle Ordnung voraussetzen, in der jedes Paar ein Supremum besitzt. Antisymmetrie liefert die Eindeutigkeit; die eindeutige Zuordnung `(x,y) ↦ sup{x,y}` bestimmt daher eine binäre Funktion. Diesen Existenzschritt ausdrücklich erklären, bevor mit der Operation gerechnet wird. Ein Auswahlaxiom ist dafür nicht erforderlich.

6. **Weshalb diese Operation die drei Rechengesetze erfüllt.** Idempotenz und Kommutativität kurz erklären. Die Assoziativität ist der Höhepunkt: Beide Klammerungen sind die kleinste obere Schranke derselben drei Elemente. Den Nachweis über die gemeinsamen oberen Schranken führen, ohne die erst zu beweisende Assoziativität oder Klammerungsunabhängigkeit vorauszusetzen.

7. **Beide Beschreibungen gewinnen einander zurück.** Von der Operation zur Ordnung und zurück entsteht dieselbe Operation; von der Ordnung zur Operation und zurück dieselbe Ordnung. Zum anfänglichen Diagramm zurückkehren. Ein kurzer Ausblick kann Maximum und die duale Infimumssicht nennen. Die gesamte Verbandstheorie, Morphismen und Frankl-Übersetzungen gehören nicht mehr in diesen Hauptgang.

Die Beweisideen in den Punkten 3, 4 und 6 müssen auch bei ausgelagerten Tabellen vollständig im Lesetext stehen. Die Ergänzung darf das Verständnis vertiefen, aber keine Lücke des Prosabeweises verdecken.

In der Rückrichtung sollten die ursprüngliche und die aus der Operation induzierte Ordnung zunächst verschiedene Zeichen tragen; erst Punkt 7 setzt sie gleich. Außerdem ist ausdrücklich abzugrenzen: Suprema aller Paare garantieren weder ein kleinstes Element noch Suprema beliebiger unendlicher Teilmengen. Gemeint ist jeweils die **kleinste**, nicht lediglich eine minimale obere Schranke.

## 4. Welche Beweistabellen ich auslagern würde

Maßgeblich ist [Band 45](<../Bd. 45 - Halbverbände und Verbände.tex>). Gezählt wurden äußere `tabproof`-Umgebungen einschließlich ihrer Varianten; Teilabschnitte einer geteilten Tabelle zählen nicht nochmals.

| Block | Tabellen | Vorhandene Kennungen |
| --- | ---: | --- |
| Träger und Auswertung, ab Zeile 490 | 3 | `JoinOrderFirstCarrier`, `JoinOrderSecondCarrier`, `JoinOrderEvaluation` |
| Ordnungsaxiome und Zusammenfassung, ab Zeile 538 | 4 | `JoinOrderReflexive`, `JoinOrderTransitive`, `JoinOrderAntisymmetric`, `JoinSemilatticeInducesOrder` |
| Operation als Paarsupremum, ab Zeile 682 | 4 | `JoinUpperLeft`, `JoinUpperRight`, `JoinLeastUpper`, `JoinIsPairSupremum` |
| Schrankenregeln der Rückrichtung, ab Zeile 909 | 3 | `PairJoinUpperLeft`, `PairJoinUpperRight`, `PairJoinLeastUpper` |
| Rechengesetze der Rückrichtung, ab Zeile 996 | 3 | `PairJoinIdempotent`, `PairJoinCommutative`, `PairJoinAssociative` |
| Halbverbandsstruktur und Rückgewinnung, ab Zeile 1166 | 2 | `PairJoinCharacterization`, `PairJoinRecoversOrder` |
| Durchgehendes Vereinigungsbeispiel, ab Zeilen 1437 und 1517 | 4 | `PowerSetUnionClosure`, `PowerSetUnionSemilattice`, `SubsetIffUnionEqualsRight`, `PowerSetUnionOrderIsInclusion` |
| **Gesamt** | **23** | **19 Kerntabellen + 4 Beispieltabellen** |

Die ersten 19 Tabellen bilden den mathematischen Kern. Die vier Beispieltabellen würde ich ebenfalls aufnehmen, damit der Beweisband das Leitbeispiel ausdrücklich dokumentiert. Die allgemeine Mengenalgebra wird dabei weiterhin aus Band 03 verwendet.

**In Band 45 bleiben die Definitionen und die vier Hauptaussagen** `JoinSemilatticeInducesOrder`, `JoinIsPairSupremum`, `PairJoinCharacterization` und `PairJoinRecoversOrder`, jeweils mit Verweis auf Lesetext und Tabellenbeweis. Auch später benutzte Hilfsaussagen bleiben als zitierbare Aussagen erhalten. Gerade hier wäre es falsch, sämtliche Hilfssätze ersatzlos aus dem Hauptband zu entfernen:

- Band 46 verwendet unter anderem `JoinOrderSecondCarrier`, `JoinOrderEvaluation`, `JoinOrderReflexive`, `JoinOrderTransitive` und `JoinOrderAntisymmetric`.
- Die späteren Abschnitte von Band 45 verwenden `JoinUpperLeft`, `JoinUpperRight` und `JoinLeastUpper` mehrfach.
- Band 46 verwendet die Rückrichtung über `PairJoinOperation`, `PairJoinCharacterization` und `PairJoinRecoversOrder` ab Zeile 4985.
- Die Übersichtsdatei zu Band 45 verweist auf die Hauptresultate und das Vereinigungsbeispiel.

Diese Verwendungen wurden in den aktiven Band-, `tex/`- und Editionsquellen gesucht. Die genannten Aussagen und ihre bestehenden Kennungen sollten deshalb stabil bleiben; ihre Tabellen können trotzdem ausgelagert werden. Ausschließlich lokale Hilfsaussagen können im Ergänzungsband einen eigenen Nummernraum erhalten. Vor einer Umsetzung sind zusätzlich die Register und PDF-Ziele abzugleichen.

**Nicht mit auslagern** würde ich die Hauptfiltercharakterisierung `JoinPrincipalFilterChar`, die allgemeine Ordnungstheorie der Bände 12–14, die Morphismenabschnitte, die vier Tabellen der infimalen Lesart sowie die spätere Theorie der Verbände und Irreduziblen. Sie sind keine notwendigen Bestandteile dieses Lesebogens.

Der Beweisband folgt derselben Reihenfolge wie die Lesefassung: Voraussetzungen, induzierte Ordnung, Paarsupremum, Rückrichtung, Rückgewinnung und Leitbeispiel. Aussagen und Voraussetzungen müssen jeweils bei der Tabelle stehen. Gemeinsame Quellen verhindern auseinanderlaufende Fassungen; Hauptband und Ergänzungen erhalten direkte Hin- und Rückverweise.

## 5. Weitere geeignete Themen

### Besonders gute Alternative: Frankls Einermengen- und Zweiermengenfall

**Titel:** „Warum ein Element in mindestens der Hälfte vorkommt – kleine Mengenglieder in vereinigungsabgeschlossenen Familien“.

Aufbau: konkrete endliche Familie und Häufigkeit → Einermengeninjektion → kurzer Fall eines gemeinsamen Elements → vier Klassen nach Zugehörigkeit zweier Elemente → Injektion von der Klasse ohne beide Elemente in die Klasse mit beiden → Vergleich der gemischten Klassen → Spezialfallsatz.

Der Schluss erklärt ausdrücklich: Die Familie enthält eine Einermenge oder Zweiermenge; ihr gesamter Träger darf größer sein. Die Lesefassung beweist diese Spezialfälle, nicht die allgemeine Vermutung. Die Vierfeldertafel macht diesen Kandidaten besonders zugänglich und liefert einen neuen kombinatorischen Beweisgedanken.

Auslagern würde ich **17 vorhandene Tabellen** im Spezialfallblock von [Band 46](<../Bd. 46 - Frankls Vermutung.tex>), Zeilen 404–1119: eine zum Einermengenfall, zwei zum nichtleeren Durchschnitt und 14 zum Zweiermengenfall. Die letzteren sind `FranklPairAvoidADecomp`, `FranklPairAvoidADisjoint`, `FranklPairContainADecomp`, `FranklPairContainADisjoint`, `FranklPairMixed01Finite`, `FranklPairMixedReverseInjection`, `FranklPairAdjDef`, `FranklPairAdjFunction`, `FranklPairAdjEval`, `FranklPairAdjInjection`, `FranklPairPositiveBranch`, `FranklPairNegativeBranch`, `FranklPairMemberFrankl`, `FranklFamPairMemberFrankl`. Die allgemeinen Werkzeuge vor diesem Block bleiben im Hauptband. Der Überblick benötigt weiterhin die erreichbare Aussage `FranklFamPairMemberFrankl`.

### Beste direkte Fortsetzung: Gruppen aus Mengenprodukten zurückgewinnen

Der positive Gegenpol zu Mogiljanskaja ist: Bei einer Gruppe lassen sich die Einermengen als die invertierbaren Elemente der Potenzhalbgruppe erkennen. Ein Isomorphismus transportiert diese Schicht und damit die ursprüngliche Gruppenoperation.

Eine kurze Lesefassung kann den Fall zweier Gruppen abschließen. Dafür genügen die drei rekonstruktionsbezogenen Tabellen `PowerGroupUnitsAreSingletons`, `PowerGroupsSingletonLayer` und `PowerGroupsSingletonTransport` in [Band 40](<../Bd. 40 - Gruppen.tex>), Zeilen 951–1126. Die benötigten Potenzmonoid- und Einheitenresultate in Band 38 besitzen bereits Prosabeweise.

Die stärkere Fassung setzt nur auf einer Seite eine Gruppe voraus und zeigt zusätzlich, dass auch die andere Grundhalbgruppe eine Gruppe ist. Sie ist ebenfalls ausgearbeitet, benötigt aber einen zweiten erheblichen Beweisabschnitt über die Einheitenmenge und ihre nichtleeren Teilmengen. Für diesen gesamten Lesebogen würde ich **12 spezielle Tabellen** aus Band 40 auslagern: die obigen drei, sieben weitere in Zeilen 1394–1940 und zwei in Zeilen 1973–2189. Sieben allgemeine Tabellen zur Einheitengruppe bleiben dort. `GroupPowerSemigroupRigidity` und `PowerGroupsSingletonTransport` müssen als zitierbare Hauptaussagen für Band 42 erhalten bleiben.

Die Rolle der **großen** Potenzhalbgruppe, also aller nichtleeren Teilmengen, muss sichtbar bleiben. Für unendliche Gruppen darf der Beweis nicht stillschweigend auf ausschließlich endliche Teilmengen übertragen werden.

### Analysis-Anschluss: Dedekindsche Schnitte und Vollständigkeit

**Titel:** „Wie die rationalen Zahlen ihre Lücken schließen“.

Der passende Aufbau wäre Schnittbedingungen → rationale Hauptschnitte → Einbettung → Inklusionsordnung → Vereinigung einer nichtleeren nach oben beschränkten Schnittfamilie → Supremumseigenschaft. Die gesamte Schnittarithmetik sollte außerhalb dieses Textes bleiben.

Vor einer Übernahme sind jedoch zwei lokale Prämissenfehler in [Band 19](<../Bd. 19 - Reelle Zahlen.tex>) zu bereinigen:

- `RealCutUnionUpperBound`, ab Zeile 1198, setzt nicht voraus, dass `S` ein reeller Schnitt ist. Eine nichtleere Familie aller rationalen Hauptschnitte hat Vereinigung `Q`; Nichtleerheit allein genügt daher nicht. Die Anwendung von `RealCutOrder` in Zeile 1215 benötigt die fehlende Mitgliedschaft.
- `RealCutUnionLeastUpperBound`, ab Zeile 1222, erlaubt eine leere Familie. Deren Vereinigung ist leer und damit kein reeller Schnitt. Auch hier wird in Zeile 1249 die nur für reelle Schnitte definierte Ordnung ohne ausreichende Voraussetzung verwendet.

Die Reparatur ist überschaubar: Beide Hilfsaussagen zunächst als reine Inklusionen formulieren und erst nach dem Schnittnachweis in reelle Vergleiche übersetzen; alternativ die nötige Schnittmitgliedschaft ergänzen. Der Vollständigkeitssatz selbst hat Nichtleerheit und Beschränktheit als Voraussetzungen und stellt die Mitgliedschaft bereits her. Dies ist **kein Gegenbeispiel zum Vollständigkeitssatz**, aber ein Grund, die Tabellen vor einer Auslagerung nicht unverändert zu übernehmen.

## Entscheidung

Für die nächste eigenständige Lesefassung empfehle ich **Halbverbände und Ordnung**: ein neuer mathematischer Blickwinkel, wenig Vorwissen, ein durchgehendes Beispiel und eine klar abgrenzbare Beweiskette. **Frankls kleine Mengenglieder** sind die beste Alternative für einen stärker kombinatorischen Text; **Gruppenrekonstruktion** ist die beste bewusste Fortsetzung des Mogiljanskaja-Themas.
