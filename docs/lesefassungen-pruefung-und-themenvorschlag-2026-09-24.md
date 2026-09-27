# Nächste Lesefassung: Gruppen aus Mengenprodukten wiedererkennen

Stand der Prüfung: 24. September 2026. Geprüft wurde der aktuelle Arbeitsstand einschließlich der noch nicht eingecheckten Änderungen. Der folgende Text dokumentiert den ursprünglichen Prüfbericht und Umsetzungsvorschlag. **Die vorgeschlagene Gruppenrekonstruktionsfassung wurde anschließend umgesetzt; siehe [Umsetzung und Prüfungen](gruppenrekonstruktion-auslagerung-2026-09-24.md).**

**Empfehlung: „Wie man eine Gruppe in ihren Mengenprodukten wiedererkennt – Einermengen, Einheiten und Gruppenrekonstruktion“, zu Band 40.** Der Text soll zunächst die Rekonstruktion zwischen zwei Gruppen erklären und anschließend den stärkeren Satz erreichen: Ist G eine Gruppe, S eine Halbgruppe und sind ihre großen Potenzhalbgruppen isomorph, dann ist auch S eine Gruppe und zu G isomorph. „Groß“ bedeutet hier: alle nichtleeren Teilmengen, einschließlich unendlicher Teilmengen.

**Für die spätere Umsetzung ausdrücklich festgehalten: Die beiden letzten inhaltlichen Abschnitte heißen „Historischer Abriss“ und danach „Schlussbemerkung“.** Die Schlussbemerkung bildet den tatsächlichen Abschluss. Editionshinweise und Quellenverweise stehen davor oder in Fußnoten. Diese Reihenfolge entspricht insbesondere den aktuellen Fassungen zu Halbverbänden und Frankl; sie ist noch nicht in allen älteren Fassungen verwirklicht.

## Umfang der Prüfung

Inhaltlich geprüft wurden die Argumentationsgänge aller acht vorhandenen Lesefassungen anhand ihrer aktuellen LaTeX-Quellen, einschließlich der von den Editionen eingebundenen historischen Abschnitte und Diagramme. In den geprüften Prosabeweisen wurde kein konkreter mathematischer Fehlschluss gefunden. Das Frankl-Beispiel mit 19 Mengen wurde zusätzlich unabhängig nachgerechnet: 19 verschiedene Mengen, Abschluss unter allen 361 Vereinigungen und Häufigkeiten 9, 9, 9, 14, 14, 14, 17.

Dies ist keine erneute vollständige Prüfung aller formalen Ableitungszeilen, historischen Angaben, PDF-Verweise oder Seitenlayouts. Für die Themenwahl wurden insbesondere die aktuellen Quellen zu Gruppenrekonstruktion, Dedekindschen Schnitten, metrischer Vollständigkeit und Wurzelwegen verglichen. Die Recherche zum historischen Rahmen der Gruppenrekonstruktion wurde mit der Originalarbeit von Liu–Tringali abgeglichen. Bestehende mathematische Quellen und PDFs wurden nicht geändert.

## Inhaltliche Befunde zu den vorhandenen Lesefassungen

**Cantor–Schröder–Bernstein.** Die kleinste abgeschlossene Hilfsmenge, ihre Fixpunktgleichung und die daraus folgende Zerlegung in zwei Bijektionszweige ergeben einen geschlossenen Beweis. Die Umkehrfunktion wird erst nach dem Nachweis einer passenden bijektiven Einschränkung verwendet. Ein durchgerechnetes Beispiel vor dem allgemeinen Argument würde den Einstieg erleichtern; die zusätzliche Schnittumformung nach der bereits erreichten Komplementgleichung lässt sich straffen. Der historische Vergleich ist vorhanden, anschließend endet die Fassung jedoch mit „Formale Fassung im Projekt“ statt einer eigenen Schlussbemerkung. Quellen: [Lesebeweis](../tex/b08/cantor-bernstein/lesebeweis.tex), insbesondere Zeilen 47–65, 86–110 und 130 ff.; [historischer Vergleich](../tex/b08/cantor-bernstein/originalbeweise.tex), Schluss ab Zeile 119; [Edition](../editions/b08-csb-reading.tex).

**Dedekindscher Rekursionssatz.** Besonders überzeugend ist die Trennung zwischen einer abgeschlossenen Relation, einem Funktionsgraphen und der eindeutig bestimmten gesamten Lösungsfunktion. Der Text benutzt die zu begründende Rekursion nicht vorweg. Das Beispiel einer nichtinjektiven Übergangsabbildung unterscheidet eindeutige Funktionswerte von Injektivität. Eine kurze ausgeführte Anwendung auf die rekursive Addition wäre eine sinnvolle Ergänzung. Das mathematische Fazit steht vor dem abschließend eingebundenen Originalvergleich; eine Schlussbemerkung danach fehlt. Quellen: [Lesetext](../tex/b10/dedekind/reading.tex), Zeilen 63–110, 163–279 und 330 ff.; [Originalvergleich](../tex/b10/dedekind/original.tex); [Edition](../editions/b10-dedekind-reading.tex).

**Ganze Zahlen.** Die Fassung liefert einen vollständigen Modellaufbau einschließlich Multiplikation, Ordnung, Normalformen, Diskretheit und zweiseitiger Induktion. Repräsentantenunabhängigkeit kommt jeweils vor der Verwendung einer Operation; natürliche Zahlen und ihre eingebettete Kopie werden unterschieden. Der breite Umfang ist sachlich gerechtfertigt, eignet sich aber nicht als Standardumfang für jede weitere Lesefassung. Bei den längeren Multiplikationsrechnungen würde ich das jeweilige Beweisziel und die entscheidenden Umformungen stärker hervorheben. Die Geschichte bildet derzeit den letzten Abschnitt; eine eigene Schlussbemerkung folgt nicht. Quelle: [Lesetext](../tex/b17/integers/reading.tex), insbesondere Zeilen 401, 654, 815, 936 und 1071 ff.

**Klammerungsunabhängigkeit.** Ein sehr gutes Vorbild für die Führung durch einen Beweis: Wort, Baum und Wert werden getrennt; das Blockgesetz folgt durch Wortinduktion und die Normalform durch Bauminduktion. Die Assoziativität der Wortkonkatenation wird nicht mit der zu beweisenden Klammerungsunabhängigkeit verwechselt. Endlichkeit, Nichtleerheit und unveränderte Reihenfolge sind ausdrücklich abgegrenzt. Eine frühe kleine Übersicht „Faktorenfolge – Rechenplan – Wert“ könnte die Orientierung noch erleichtern. Der aktuelle Text endet mit „Was das Ergebnis erlaubt“; historischer Abriss und anschließende eigene Schlussbemerkung fehlen. Quelle: [Lesetext](../tex/b28/bracketing/reading.tex), insbesondere Zeilen 98, 235, 327, 421 und 496–538; [Edition](../editions/b28-bracketing-reading.tex).

**Mogiljanskaja-Gegenbeispiel.** Die Konstruktion erklärt die entscheidenden Schwierigkeiten tatsächlich: Produktinformationen, eine Reserve außerhalb der Produktrechtecke, explizite Bijektionen und Multiplikationserhaltung. Das Beispiel einer Dreiermenge, die auf die neue Einermenge abgebildet wird, zeigt den Informationsverlust besonders gut. Es könnte bereits am Anfang als Vorschau stehen. Wegen der zahlreichen Mengen und Abbildungen würde ich eine kurze Notationsübersicht und deutlichere Zwischenziele einfügen. Die historische Passage trennt den Originalbeweis von der eigenen konkreten Reservekonstruktion, steht aber nach dem Fazit ganz am Ende. Quelle: [Lesetext](../tex/b28/mogiljanskaja/reading.tex), Zeilen 135–263, 445 ff., 561–598 und 600 ff.

**Formale Differenzen.** Gegenüber der Ganzzahlfassung besteht eine klare eigenständige Aufgabe: allgemeine Gruppenbildung und die Rolle der Kürzbarkeit. Besonders gut sind die genaue Verwendung der Kürzbarkeit bei der Transitivität, das Beispiel mit zwei Ganzzahlkoordinaten und das Maximum-Gegenbeispiel. Die additive Quotientenkonstruktion überschneidet sich absichtlich mit Band 17; die weiterführenden Ziele unterscheiden sich. Das Koordinatenbeispiel würde ich früher ankündigen. Ein historischer Abriss fehlt aktuell; der Abschnitt „Anschluss an die beiden Bände“ ersetzt das gewünschte Paar aus Historie und Schlussbemerkung nicht. Quelle: [Lesetext](../tex/b41/differences/reading.tex), Zeilen 134, 218–261, 404–476 und 480–547.

**Halbverbände und Ordnung.** Das stärkste Gesamtvorbild: Ein kleines Vereinigungsbeispiel trägt beide Richtungen zwischen Operation und Ordnung. Existenz und Eindeutigkeit der Supremumsoperation werden begründet; ihre Assoziativität wird über das Supremum dreier Elemente bewiesen und nicht vorausgesetzt. Das Maximumbeispiel auf den ganzen Zahlen zeigt die Grenzen bezüglich kleinstem Element und unendlicher Suprema. Historischer Abriss und Schlussbemerkung stehen bereits in der gewünschten Reihenfolge am Ende. Quelle: [Lesetext](../tex/b45/semilattice/reading.tex), Zeilen 305–344, 407–466, 485 ff., 553–589, 603 und 680 ff.

**Frankls Spezialfälle.** Die aktuelle Fassung enthält bereits das Dreierbeispiel. Der Einermengen- und Zweiermengenbeweis trennt Vereinigungsabschluss, Injektivität und disjunkte Zielklassen sauber. Die anschließende Zählgleichung erklärt denselben Gedanken nochmals knapp. Das Beispiel mit 19 Mengen widerlegt nur die lokale Behauptung, eines der drei Elemente eines gegebenen Dreiermitglieds müsse halbhäufig sein; es ist kein Gegenbeispiel zur allgemeinen Frankl-Vermutung. Diese Grenze ist im Text korrekt benannt. Historischer Abriss und Schlussbemerkung sind vorhanden. Quelle: [Lesetext](../tex/b46/frankl/reading.tex), Zeilen 244–330, 362–475, 478–579, 590 und 654 ff.; die [Beweisedition](../editions/b46-frankl-proofs.tex) bindet auch die zusätzliche Dreierherleitung ein.

Die nächste Fassung sollte das durchgehende Beispiel von Band 45, die Beweisführung der Klammerungsfassung und die explizite Behandlung der Grenzen aus Band 41 und Band 46 verbinden. Anschauliche Multiplikations- und Inzidenztafeln gehören weiterhin in die Lesefassung; ausgelagert werden die formallogischen Ableitungstabellen.

## Warum Gruppenrekonstruktion als Nächstes

Das Thema ist die natürliche Gegenfrage zum Mogiljanskaja-Text: Dort gehen die Einermengen als erkennbare Schicht verloren; bei Gruppen lassen sie sich allein anhand der Multiplikation als Einheiten wiederfinden. Man benötigt weder die schwierige Reservekonstruktion noch die gesamte Halbgruppentheorie, um die neue Frage zu verstehen.

Der erste Erfolg wird früh erreicht: Zwei Gruppen mit isomorphen Potenzhalbgruppen sind isomorph. Der anschließende Ausbau beantwortet eine stärkere Frage: Die zweite Struktur braucht zunächst nur eine Halbgruppe zu sein. Damit entsteht ein eigener Spannungsbogen mit einem einfachen Einstieg und einem gehaltvollen Schluss.

Hauptquelle ist [Band 40](<../Bd. 40 - Gruppen.tex>), Abschnitt „Rekonstruktion aus der großen Potenzhalbgruppe“, ab Zeile 929. Der einfache Rekonstruktionssatz trägt im aktuellen Register die Nummer **40.3.3.4**, der stärkere Hauptsatz **40.3.3.19**. Der vollständige Text könnte ungefähr **10–14 PDF-Seiten** umfassen; das ist eine redaktionelle Zielgröße, kein ermittelter Satzumfang.

## Vorgeschlagener Aufbau

1. **Kann man die ursprünglichen Elemente noch erkennen?** Die Frage durch Mengenprodukte einführen: XY besteht aus allen Produkten xy mit x aus X und y aus Y. Den Anschluss an Mogiljanskaja kurz erklären, die neue Fassung aber unabhängig lesbar machen. Ziel: Rekonstruktion aus der Multiplikation der nichtleeren Teilmengen, ohne vorausgesetzte Erhaltung von Inklusion oder Mengengröße.

2. **Ein vollständiges kleines Beispiel.** Für die Zweiergruppe G = {e,s} mit s² = e die drei nichtleeren Teilmengen {e}, {s}, G und ihre 3×3-Multiplikationstafel zeigen. {e} ist neutral, {s} ist invertierbar, G absorbiert alle drei Teilmengen. In dieser Tabelle die beiden ursprünglichen Gruppenelemente wiederentdecken.

3. **Der Schlüssel: Einheiten sind genau Einermengen.** Eine Einheit als Element mit zweiseitigem Inversen erklären. Für Gruppen ist jede Einermenge invertierbar. Umgekehrt erzwingt XY = YX = {e}, dass X und Y Einermengen sind. Den Beweis vollständig lesen lassen, nicht bloß auf eine Tabelle verweisen. Für den späteren Ausbau gleich festhalten: In einem beliebigen Monoid sind die Einheiten seiner Potenzhalbgruppe genau die Einermengen seiner invertierbaren Elemente.

4. **Aus dem großen Isomorphismus wird ein Gruppenisomorphismus.** Isomorphismen erhalten neutrales Element und Einheiten. Sind beide Ausgangsstrukturen Gruppen, gibt es daher eindeutig φ(g) mit F({g}) = {φ(g)}. Die Bijektivität und die Gleichung φ(gh) = φ(g)φ(h) unmittelbar aus Einermengenprodukten herleiten. Damit ist der erste Rekonstruktionssatz bewiesen. Eine kleine Abbildung zwischen den Ebenen „Element – Einermenge – Bild“ unterstützt die Erklärung.

5. **Warum eine einzige bekannte Gruppe genügt: das Ziel zunächst zum Monoid machen.** Jetzt die stärkere Voraussetzung ausdrücklich wechseln: G ist Gruppe, S zunächst nur Halbgruppe. Das Bild von {e} ist ein neutrales Element der Potenzhalbgruppe von S. Erklären, weshalb dieses selbst eine Einermenge {u} sein muss und u ein neutrales Element von S ist. Erst danach die Einheitengruppe von S verwenden.

6. **Die ganze Einheitenmenge wiederfinden.** Für Monoide A und B ihre Einheitenmengen U und V einführen. Sie sind selbst nichtleere Teilmengen und damit Elemente der großen Potenzhalbgruppen. Einheitenstabilität bedeutet, dass Multiplikation von links oder rechts mit jeder Einheit das betreffende Element unverändert lässt. Diese Eigenschaft wird durch Isomorphismen erhalten. Sie allein charakterisiert U aber nicht eindeutig: Im multiplikativen Monoid der ganzen Zahlen sind etwa sowohl {−1,1} als auch {−2,2} unter den Einheiten stabil. Deshalb das Argument mit beiden Richtungen vollständig zeigen: Für X = F⁻¹(V) gilt UX = X, also F(U)V = V; aus der Stabilität von F(U) folgt zugleich F(U)V = F(U). Damit F(U) = V. Grundlage ist die vorhandene Beweiskette in Band 40, insbesondere `LargePowerUnitSetImage`.

7. **Von einer Teilmenge zur ganzen Familie und zurück zur Gruppe.** Für nichtleeres Y gilt Y ⊆ U genau dann, wenn YU = U. Dieses Produktkriterium ersetzt eine nicht vorausgesetzte Erhaltung von Inklusion. Es liefert mit F und F⁻¹, dass F die Familie aller nichtleeren Teilmengen von U auf die entsprechende Familie von V abbildet. Bei der Ausgangsgruppe ist U = G. Wegen der Surjektivität von F muss daher jede nichtleere Teilmenge von S in V liegen; bereits die Einermengen ergeben S = V. Also ist S eine Gruppe. Nun den bereits bewiesenen Schritt 4 anwenden.

8. **Reichweite und Grenzen.** Keine Endlichkeitsannahme und keine Kommutativität sind nötig. Wesentlich für den stärkeren Beweis ist aber, dass die ganze Einheitengruppe als Teilmenge zugelassen ist. Für unendliche Gruppen darf dieser Ausbau nicht einfach auf nur endliche nichtleere Teilmengen übertragen werden. Auch wird nicht behauptet, der ursprüngliche Isomorphismus F sei auf jeder Teilmenge schon durch punktweise Anwendung von φ gegeben. Bewiesen ist die Bestimmung der Grundgruppe und der Transport ihrer Einermengen. Den Gegensatz zum Mogiljanskaja-Beispiel nochmals konkret benennen.

9. **Historischer Abriss.** Die Arbeiten von Tamura und Shafer aus den 1960er Jahren und Shafers kurzen Gruppenbeweis einordnen, anschließend Mogiljanskajas Gegenbeispiel von 1973 als Grenze der allgemeinen Rekonstruktionsfrage erklären. Den stärkeren Satz mit nur einer vorausgesetzten Gruppe ausdrücklich von dem älteren Satz für zwei Gruppen unterscheiden und Liu–Tringali (2026) zuordnen. Die Geschichte soll die beiden Beweisstufen erklären, kein vollständiger Forschungsbericht werden. Quellen in Fußnoten; Originaldarstellung und unsere didaktische Aufbereitung auseinanderhalten.

10. **Schlussbemerkung.** Zur kleinen Multiplikationstafel und zur Eingangsfrage zurückkehren: Invertierbarkeit macht die ursprünglichen Elemente algebraisch erkennbar; der Transport der gesamten Einheitenmenge erklärt, weshalb auch ein zunächst unbekannter Zieltyp eine Gruppe sein muss. Der letzte Absatz benennt das erreichte Resultat und seine genaue Reichweite. Danach folgt kein weiterer inhaltlicher Abschnitt.

Bei der Notation ist besonders zwischen **F(U)** als Bild eines einzelnen Elements der Potenzhalbgruppe und **F[P₊(U)]** als Bild einer ganzen Teilmengenfamilie zu unterscheiden. Diese Unterscheidung gehört ausdrücklich in den Lesetext.

## Historische Ausgangsquellen

Die [Originalarbeit von Liu–Tringali, „Power Semigroups and Two Rigidity Theorems for Groups“ (2026)](https://arxiv.org/html/2606.01917v1) enthält den stärkeren Satz als Theorem 1.3 und den Transport der Einheitengruppen als Theorem 2.3. Einleitung und Literaturverzeichnis nennen Tamura–Shafer, *Power semigroups*, Math. Japon. 12 (1967), 25–32, sowie Shafer, *Note on power semigroups*, ebenda, S. 32. Für die endgültige historische Ausarbeitung sollte Shafers kurze Originalnotiz zusätzlich direkt beschafft und verglichen werden; hier wurde ihre Darstellung nicht als selbst eingesehen ausgegeben.

Mogiljanskajas [Originalarbeit von 1973](https://doi.org/10.1007/BF02389140) ist bereits Gegenstand der vorhandenen Lesefassung. Die dort ausgearbeitete Trennung zwischen Originalargument und eigener Reservekonstruktion ist auch für den neuen historischen Vergleich maßgeblich. Den aktuellen Forschungsstand bei der späteren Umsetzung gegebenenfalls erneut prüfen; die geplante mathematische Aussage selbst ist präzise festgelegt.

## Genau diese Beweistabellen würde ich auslagern

**Zwölf vorhandene äußere `tabproof`-Umgebungen aus Band 40.** Eine mehrteilige Umgebung zählt als eine Tabelle; intern benannte Beweisteile kommen mit, werden aber nicht zusätzlich gezählt. Zeilen und Nummern beziehen sich auf den am 24. September gelesenen Arbeitsstand.

| Aussage | Kennung | Nummer | Tabelle, Quellzeilen |
| --- | --- | --- | --- |
| Einheiten der Gruppenpotenzhalbgruppe sind Einermengen | `PowerGroupUnitsAreSingletons` | 40.3.3.2 | 963–1012 |
| Isomorphismen erhalten die Einermengenschicht | `PowerGroupsSingletonLayer` | 40.3.3.3 | 1028–1074 |
| Konkreter Transport der Gruppenelemente | `PowerGroupsSingletonTransport` | 40.3.3.4 | 1093–1124 |
| Der volle Gruppenträger absorbiert nichtleere Teilmengen | `GroupPowerFullCarrierAbsorption` | 40.3.3.10 | 1402–1527 |
| Transport der Einheitenstabilität | `SemigroupIsoUnitStabilityTransport` | 40.3.3.11 | 1545–1602 |
| Einheitenstabilität der ganzen Einheitenmenge | `PowerMonoidUnitSetStable` | 40.3.3.12 | 1613–1644 |
| Absorption durch die Einheitenmenge | `PowerMonoidUnitStableAbsorption` | 40.3.3.13 | 1657–1770 |
| Produktkriterium für Teilmengen der Einheitenmenge | `PowerMonoidUnitSubsetCriterion` | 40.3.3.14 | 1781–1826 |
| Bild der gesamten Einheitenmenge | `LargePowerUnitSetImage` | 40.3.3.15 | 1840–1897 |
| Bilder ihrer nichtleeren Teilmengen | `LargePowerUnitSubsetImage` | 40.3.3.16 | 1908–1939 |
| Transport der gesamten Teilmengenfamilie | `LargePowerSemigroupUnitGroupReconstruction` | 40.3.3.18 | 1996–2077 |
| Einseitige Gruppenstarrheit | `GroupPowerSemigroupRigidity` | 40.3.3.19 | 2112–2187 |

Der interne Hilfssatz `GroupPowerFullCarrierAbsorptionProductMember` gehört zur vierten Tabelle. Sein Verweisziel muss erhalten bleiben, weil spätere Tabellen ihn gesondert benutzen.

**Sieben allgemeine Grundlagentabellen desselben Abschnitts bleiben in Band 40:** `GroupElementIsMonoidUnit`, `MonoidUnitSetInverse`, `MonoidInversePairProduct`, `MonoidUnitSetProduct`, `MonoidUnitSetCarrier`, `MonoidUnitSetIsGroup` und `GroupUnitSetIsCarrier`. Sie entwickeln die allgemeine Einheitengruppentheorie und sind nicht bloß technische Nebenrechnungen des Rekonstruktionssatzes.

Auch die allgemeinen Grundlagen über Mengenprodukte und Einermengenrekonstruktion in Band 28 sowie über Potenzmonoide, neutrale Elemente und Einheiten in Band 38 bleiben dort. Insbesondere hat `PowerMonoidUnitCharacterization` in Band 38 derzeit einen **Prosabeweis**, keine vorhandene Beweistabelle; dieser darf nicht als zusätzlich auszulagernde Tabelle gezählt werden. Der Lesetext erklärt seinen kurzen entscheidenden Gedanken selbst, der Beweisband verweist auf die allgemeine Aussage.

## Was in Fachband und Lesefassung erhalten bleiben soll

Nach dem Vorbild von Band 45 würde ich **Definitionen, Satzaussagen, Nummern und bisherige Verweisziele in Band 40 und im Gesamtband erhalten** und die zwölf Ableitungen in einen Ergänzungsband verlegen. Die beiden Rekonstruktionssätze bekommen direkte Verweise auf Lesefassung und Tabellenbeweis. Gemeinsame Quellen vermeiden auseinanderlaufende Fassungen.

Eingehende Verweise sind bereits vorhanden: [Band 42](<../Bd. 42 - Endliche Gruppen.tex>), Zeilen 230 und 249, benutzt `GroupPowerSemigroupRigidity` und `PowerGroupsSingletonTransport`; die [Übersicht zu Band 40](../tex/ueberblick/b40.tex), Zeilen 44 und 56–57, verweist zusätzlich auf `LargePowerSemigroupUnitGroupReconstruction`. Diese Aussagen dürfen durch die Auslagerung nicht verschwinden oder stillschweigend neue Nummern bekommen.

Im Lesetext bleiben die vollständigen tragenden Argumente: Erkennung der Einermengen, Konstruktion von φ, Gewinnung des neutralen Zielelements, Gleichheit F(U) = V, Produktkriterium und Schluss \(S=S^\times\), wobei \(S^\times\) hier die Einheitengruppe bezeichnet. Die Tabellen übernehmen das formale Ausrollen, nicht die gedankliche Begründung.

Vorgesehene Ablage: `output/08 Gruppen/Ergänzungen/Gruppenrekonstruktion/`, mit eigener Lesefassung und eigenem Beweisband. Bei der Umsetzung sind Quellenzuordnung, Nummern, eingehende Verweise, Hilfssatzanker und PDF-Ziele zu prüfen. Der jetzige Bericht nimmt weder Auslagerung noch PDF-Bau vorweg.

## Weitere geeignete Themen und ihre Vorarbeiten

**Dedekindsche Schnitte und Vollständigkeit, Band 19.** Der stärkste Kandidat für einen späteren Wechsel zur Analysis: rationale Anfangsabschnitte → Schnittbedingungen → rationale Einbettung → totale Inklusionsordnung → Vereinigung als Supremum. Dafür lassen sich 13 äußere Tabellen abgrenzen: zehn zu Schnittbegriff, rationaler Darstellung und Ordnung (Zeilen 126–770) sowie `RealBoundedCutUnionIsCut`, `RealLeastUpperBoundProperty`, `RealCutSupremumUnion` (984–1331). Schnittarithmetik und Infima wären nicht Teil dieses Lesebogens.

Zwei früher festgestellte Probleme bestehen in der aktuellen Quelle fort: `RealCutUnionUpperBound` (1197–1218) setzt die Schnittmitgliedschaft der Vereinigung nicht voraus; die Vereinigung aller rationalen Hauptschnitte ist jedoch ganz Q. `RealCutUnionLeastUpperBound` (1220–1250) lässt die leere Familie zu, deren Vereinigung ebenfalls kein reeller Schnitt ist. `RealCutOrder` (432–439) verlangt dagegen beide Argumente in R. Vor einer Auslagerung sollten die Hilfsaussagen als reine Inklusionsaussagen formuliert oder um die fehlenden Schnittvoraussetzungen ergänzt werden, einschließlich ihrer Aufrufe. Die Hauptsätze haben die richtigen Annahmen; ihr mathematischer Inhalt wird durch diesen Befund nicht widerlegt.

**Bäume durch eindeutige Wurzelwege erkennen, Band 26.** Anschaulicher graphentheoretischer Gegenpol: Ein Knoten mit genau einem einfachen Weg zu jedem anderen Knoten genügt für das Baumkriterium. Sieben Tabellen bilden einen engen Kern (`RootPathsGivePairPath` bis `RootedTreeIffUniqueRootPaths`, Zeilen 3295–3634). Vorher wäre aber der entscheidende Schritt in `RootPathUniquenessTransfers` auszubauen: Die Begründung „Erster Kreisabschnitt und kürzester Wurzelweg zu diesem endlichen Kreis“ um Zeile 3410 ersetzt dort noch mehrere formale Schritte. Das richtige Argument ist in der Prosa erklärt; für eine vollständige Tabellenfassung ist zusätzliche Arbeit nötig.

**Cauchy-Folgen und vollständige Räume, Band 47.** Ein guter eigenständiger Lesebogen wäre „Wenn ein Grenzpunkt fehlt“: Konvergenz und Cauchy-Bedingung, die punktierte reelle Gerade, vollständige diskrete Räume und abgeschlossene Teilräume vollständiger Räume. Band 47 enthält allerdings 44 Prosabeweise und keine `tabproof`-Umgebungen. Er behandelt Vollständigkeit, keine Konstruktion einer Vervollständigung. Deshalb ist er für einen neuen erklärenden Text geeignet, für die gewünschte Verbindung mit der Auslagerung vorhandener Tabellen aber weniger ergiebig.

Die Gruppenrekonstruktion erhält den Vorzug: ein klarer Anschluss an eine bestehende Lesefassung, ein eigenständiger mathematischer Gedanke, zwei aufeinander aufbauende Resultate und zwölf bereits konkret abgegrenzte Beweistabellen. Historischer Abriss und abschließende Schlussbemerkung sind fester Bestandteil dieses Vorschlags.
