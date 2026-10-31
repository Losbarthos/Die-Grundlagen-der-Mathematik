# Ausbauplan ab Band 49

Stand: 26. Oktober 2026

Der Ausbau umfasst die geplanten Bände 49 bis 108. Jeder Band erhält eine bestimmte Strukturklasse oder Abbildungsklasse mit ausdrücklich genannten Grunddaten und Bedingungen. Die Nummerierung ist eine mögliche Reihenfolge ohne Rückgriffe auf noch spätere Bände; die mathematischen Abhängigkeiten verzweigen sich. Die Reihenfolge der tatsächlichen Ausarbeitung kann einem der unten angegebenen Lesepfade folgen.

Der erste Arbeitsblock führt von Körpern zu Vektorräumen. Danach entstehen die Zweige Geometrie, Analysis, Maßtheorie, Wahrscheinlichkeit und Statistik. Kontraktive Funktionensysteme erlauben einen frühen Einstieg in die fraktale Geometrie. Numerische Verfahren werden als Begleitfassungen den jeweils tragenden Strukturen zugeordnet.

## Regeln für Bandgrenzen und Abhängigkeiten

1. Ein Strukturband hat feste Grunddaten, einen abgegrenzten Axiomkern, passende strukturtreue Abbildungen und eine eigene Theorie. Spezialisierungen wie endliche Dimension, Vollständigkeit oder Normierung werden als solche benannt.
2. Abbildungsklassen dürfen eigene Bände bilden, entsprechend den vorhandenen Bänden über injektive, surjektive und bijektive Funktionen. Eine Differenzierbarkeitsbedingung ist eine definierende Strukturbedingung und kein zusätzliches mengentheoretisches Grundaxiom.
3. Axiome gelten für die untersuchten Objekte. Die Existenz konkreter Modelle, des Integrals, einer Vervollständigung oder eines Attraktors wird bewiesen.
4. Eine andere Darstellung derselben Struktur wird durch einen Äquivalenzsatz verbunden. Eine Mengenalgebra ist beispielsweise eine konkrete Boolesche Algebra; ihre Darstellung als Teilmengenstruktur erhält eine eigene Rolle, ohne die abstrakte Theorie nochmals aufzubauen.
5. Ein Parameter wie Dimension n oder Regularitätsgrad k bleibt innerhalb einer einheitlichen Bandtheorie. Es entstehen keine gesonderten Bände für jede Dimension und jede Ableitungsordnung. Auch wird nicht jede mögliche Kombination sämtlicher Zusatzbedingungen zu einem Band.
6. Die algebraischen Bände arbeiten über allgemeinen Körpern beziehungsweise Ringen. Skalarprodukt, Normen, Analysis und Mannigfaltigkeiten werden zunächst reell entwickelt. Komplexe Zahlen und komplexe beziehungsweise hermitesche Strukturen bleiben einem späteren Ausbau vorbehalten.

In den Tabellen bedeutet **S**: unmittelbare Strukturgrundlage. **W** bezeichnet weitere Voraussetzungen für die vorgesehenen Konstruktionen, Hauptsätze oder den Anschluss an vorhandene Modelle. Bereits über diese Bände mitgebrachte Grundlagen werden nicht nochmals aufgezählt. Die allgemeinen Sprachmittel der Bände 01 bis 08 sind überall verfügbar.

Die Abhängigkeiten legen die inhaltliche Schnittstelle fest; sie sind noch keine Inventur sämtlicher späterer Beweisaufrufe. Auswahlprinzipien aus Band 09 beziehungsweise 16 müssen am einzelnen Satz ausgewiesen werden. Insbesondere werden weder der allgemeine Vektorraumbasissatz noch beliebige kompakte Produkte stillschweigend als auswahlfrei behandelt. Band 48 mit Forcing und Unabhängigkeitsbeweisen ist keine allgemeine Voraussetzung dieser Fortsetzung.

## Vorhandene Grundlagen

| Bestand | Anschluss und Grenze |
| --- | --- |
| Band 19 Reelle Zahlen | Vollständig angeordneter Körper, Dedekindsches Modell und Eindeutigkeit sind bereits vorhanden. Band 51 behandelt die allgemeinere Klasse ohne Vollständigkeitsbedingung. |
| Band 21 Folgen | Rekursion, Konvergenz und Cauchy-Folgen liefern die Ausgangssprache für Analysis und abzählbare Konstruktionen. Nichtnegative Reihen und erweiterte nichtnegative reelle Zahlen werden bei Bedarf ausdrücklich eingeführt. |
| Band 44 Kommutative Ringe mit Eins | Ausgangspunkt für Integritätsbereiche und Körper. |
| Band 45 Halbverbände und Verbände | Ausgangspunkt für Boolesche Algebren und Vektorverbände. |
| Band 47 Metrische Räume und Vollständigkeit | Metrik, Stetigkeit, Vollständigkeit und metrische Kompaktheit werden übernommen. Für diese bereits behandelten Klassen werden keine neuen Parallelbände angelegt. |
| Leitfaden zu Band 47 | Fixpunktsätze, metrische Funktionenräume und Hausdorffmetrik sind bereits als beweisfreie Ergebnisse skizziert. Die erforderlichen Beweise erhalten im Ausbau einen kanonischen Ort: Fixpunkttheorie in Band 68, Hausdorffmetrik und ihre Vollständigkeit als Modellkonstruktion in Band 104. |

Die bisher vorhandenen Bündel in Band 45 und 47 bleiben bestehen. Ihre nachträgliche Aufteilung gehört nicht zu diesem Ausbauplan.

## Bände 49 bis 58 Algebra und affine Geometrie

| Band | Titel und Grunddaten | Strukturaxiome | Direkte Voraussetzungen |
| --- | --- | --- | --- |
| 49 | **Integritätsbereiche**; kommutativer Ring R mit Eins | 0 ≠ 1; aus ab = 0 folgt a = 0 oder b = 0. | S: 44; W: — |
| 50 | **Körper**; Integritätsbereich K | Für jedes a ≠ 0 gibt es b mit ab = 1. Gleichwertig: nichttrivialer kommutativer Ring mit Eins, dessen Nichtnullelemente invertierbar sind. | S: 49; W: 18, 19 |
| 51 | **Angeordnete Körper**; Körper K mit ≤ | ≤ ist eine totale Ordnung; a ≤ b impliziert a + c ≤ b + c; a,b ≥ 0 impliziert ab ≥ 0. Die Folgerung 0 < 1 wird nachgewiesen. | S: 50, 15; W: 19 |
| 52 | **Module**; Ring R mit Eins, abelsche Gruppe M, skalare Wirkung R × M → M | r(x + y) = rx + ry; (r + s)x = rx + sx; (rs)x = r(sx); 1x = x. Gemeint sind unitäre Linksmoduln; Kommutativität von R wird nicht verlangt. | S: 43, 41; W: — |
| 53 | **Vektorräume**; Modul V über K | Der Skalarring K ist ein Körper. Die Modulaxiome werden übernommen. Lineare Abbildungen erhalten Addition und Skalarmultiplikation. | S: 52, 50; W: — |
| 54 | **Endlichdimensionale Vektorräume**; Vektorraum V | Es gibt endlich viele v₁,…,vₙ, sodass jedes v eindeutig als Summe a₁v₁ + ⋯ + aₙvₙ darstellbar ist. Der Fall n = 0 ist zugelassen. | S: 53; W: 20 |
| 55 | **Affine Räume**; nichtleere Punktmenge A, Vektorraum V, Wirkung A × V → A | p + 0 = p; (p + u) + v = p + (u + v); für p,q ∈ A gibt es genau ein v ∈ V mit p + v = q. | S: 53; W: — |
| 56 | **Reelle Skalarprodukträume**; reeller Vektorraum V mit Bilinearform b | b ist symmetrisch; b(v,v) > 0 für v ≠ 0. Vollständigkeit und endliche Dimension werden nicht vorausgesetzt. | S: 53, 19; W: — |
| 57 | **Euklidische Vektorräume**; reeller Skalarproduktraum V | V ist endlichdimensional. Seine metrische Vollständigkeit wird aus diesen Voraussetzungen bewiesen. | S: 56, 54; W: 47 |
| 58 | **Euklidische affine Räume**; affiner Raum A mit Translationsraum V | V ist ein euklidischer Vektorraum. Der Abstand wird aus dem Skalarprodukt des Verschiebungsvektors definiert. | S: 55, 57; W: — |

Band 49 entwickelt insbesondere Quotientenkonstruktionen, deren Körpernachweis in Band 50 anschließt. Band 50 verallgemeinert die bei rationalen und reellen Zahlen schon verwendeten Körpergesetze. Band 53 behandelt lineare Abbildungen, Unterräume und Quotienten; Band 54 trägt Matrizen, Rang, Determinanten und lineare Gleichungssysteme.

Band 56 beweist Cauchy–Schwarz und die Normeigenschaften der Quadratwurzel von b(v,v). Die Existenz positiver Quadratwurzeln muss aus der reellen Vollständigkeit hergeleitet sein. Diese Konstruktion nimmt die allgemeine Normraumtheorie nicht voraus. Band 57 behandelt Orthogonalbasen und endlichdimensionale Projektionen; Band 58 behandelt Punktgeometrie, Abstände, Winkel und Bewegungen ohne ausgezeichneten Ursprung.

## Bände 59 bis 68 Normen Topologie und Kontraktionen

| Band | Titel und Grunddaten | Strukturaxiome | Direkte Voraussetzungen |
| --- | --- | --- | --- |
| 59 | **Seminormierte reelle Räume**; reeller Vektorraum V mit p: V → [0,∞) | p(av) = abs(a)p(v); p(u + v) ≤ p(u) + p(v). Nichtnullvektoren mit p(v) = 0 sind zugelassen. | S: 53, 19; W: — |
| 60 | **Normierte reelle Räume**; seminormierter Raum (V,p) | p(v) = 0 impliziert v = 0. Daraus entsteht die Metrik d(u,v) = p(u − v). | S: 59; W: 47, 54 |
| 61 | **Reelle Banachräume**; normierter Raum V | Jede Cauchy-Folge bezüglich der induzierten Metrik konvergiert in V. | S: 60, 47; W: — |
| 62 | **Reelle Hilberträume**; reeller Skalarproduktraum V | V ist bezüglich der vom Skalarprodukt induzierten Norm vollständig. | S: 56, 47; W: 60, 61 |
| 63 | **Topologische Räume**; Menge X mit τ ⊆ P(X) | ∅ und X liegen in τ; beliebige Vereinigungen und endliche Schnitte von Mitgliedern von τ liegen in τ. | S: 03; W: 47 |
| 64 | **Hausdorffräume**; topologischer Raum X | Zwei verschiedene Punkte besitzen disjunkte offene Umgebungen. | S: 63; W: — |
| 65 | **Kompakte topologische Räume**; topologischer Raum X | Jede offene Überdeckung von X besitzt eine endliche Teilüberdeckung. Hausdorffheit ist kein Grundaxiom. | S: 63; W: 20, 47 |
| 66 | **Zusammenhängende topologische Räume**; topologischer Raum X | Die einzigen gleichzeitig offenen und abgeschlossenen Teilmengen sind ∅ und X. Gleichwertig: keine Zerlegung in zwei nichtleere disjunkte offene Mengen. | S: 63; W: 19 |
| 67 | **Lipschitz-stetige Abbildungen**; metrische Räume X,Y und f: X → Y | Es gibt L ≥ 0 mit d_Y(f(x),f(y)) ≤ L d_X(x,y) für alle x,y. | S: 47; W: — |
| 68 | **Kontraktive Selbstabbildungen vollständiger metrischer Räume**; nichtleerer vollständiger metrischer Raum X mit T: X → X | Es gibt q mit 0 ≤ q < 1 und d(Tx,Ty) ≤ q d(x,y). | S: 67, 47; W: 21 |

Im Hauptteil von Band 59 werden Kern und induzierte Pseudometrik behandelt. Die allgemeine Theorie des normierten Quotienten wird in Band 60 nach Einführung des Normbegriffs bewiesen. Band 60 behandelt stetige lineare Operatoren und Operatornormen sowie die Äquivalenz von Normen in endlicher Dimension. Band 61 enthält vollständige Funktionenräume und konvergente Reihen, Band 62 den Projektionssatz und beste Approximation.

Band 63 enthält Teilraum-, Produkt- und Quotiententopologien sowie stetige Abbildungen und Homöomorphismen. Die Bände 64 bis 66 sind verschiedene Zweige, keine Kette zunehmend stärkerer Voraussetzungen. Insbesondere gilt die Gleichwertigkeit von Folgenkompaktheit und Kompaktheit aus Band 47 nicht für beliebige topologische Räume.

Band 68 enthält den Banachschen Fixpunktsatz einschließlich a-priori- und a-posteriori-Fehlerabschätzungen. Ein Banachraum ist dafür nicht erforderlich. Die Klasse enthält Quelle, Metrik und ausgezeichnete Selbstabbildung; sie ist enger als die allgemeine Klasse vollständiger metrischer Räume.

## Bände 69 bis 79 Analysis und dynamische Systeme

| Band | Titel und Grunddaten | Strukturaxiome oder definierende Bedingungen | Direkte Voraussetzungen |
| --- | --- | --- | --- |
| 69 | **Differenzierbare reelle Funktionen**; offene Menge U ⊆ R, f: U → R | Für jedes x ∈ U existiert der endliche Grenzwert des Differenzenquotienten bei h → 0. | S: 19, 47; W: 21, 66 |
| 70 | **Differenzierbare Abbildungen normierter Räume**; reelle normierte Räume E,F, offenes U ⊆ E, f: U → F | Für jedes x gibt es einen stetigen linearen Operator Aₓ mit f(x + h) = f(x) + Aₓh + rₓ(h) und norm(rₓ(h))/norm(h) → 0. | S: 60; W: 69 |
| 71 | **Stetig differenzierbare Abbildungen**; Daten aus Band 70, festes k ≥ 1 oder k = ∞ | Die Fréchet-Ableitungen bis zur Ordnung k existieren und sind stetig; bei k = ∞ gilt dies für jede endliche Ordnung. Die Ableitungen werden in den normierten Räumen stetiger multilinearer Abbildungen betrachtet. | S: 70; W: 61, 68 |
| 72 | **Riemann-integrierbare Funktionen**; a < b in R, beschränktes f: [a,b] → R | Zu jedem ε > 0 existiert eine endliche Zerlegung Z mit Obersumme(f,Z) − Untersumme(f,Z) < ε. Das Integral wird als gemeinsamer Wert von Ober- und Unterintegral konstruiert. | S: 19, 21; W: 47, 69, 71 |
| 73 | **Monoidwirkungen**; Monoid M, Menge X, α: M × X → X | α(e,x) = x und α(mn,x) = α(m,α(n,x)). Die Wirkung von (N,+) entspricht einem diskreten dynamischen System. | S: 38; W: 10, 21 |
| 74 | **Stetige Halbflüsse**; topologischer Raum X, Φ: [0,∞) × X → X | Φ ist gemeinsam stetig; Φ(0,x) = x; Φ(s + t,x) = Φ(s,Φ(t,x)). | S: 73, 63, 19; W: — |
| 75 | **Stetige globale Flüsse**; topologischer Raum X, Φ: R × X → X | Φ ist gemeinsam stetig und erfüllt Identitäts- und Wirkungsgesetz für alle reellen Zeiten. Insbesondere sind negative Zeiten zugelassen. | S: 73, 63, 19; W: 74 |
| 76 | **Stetige zeitabhängige Vektorfelder**; offenes Intervall I, offenes U ⊆ Rⁿ, F: I × U → Rⁿ | F ist gemeinsam stetig. Das Anfangswertproblem lautet x′(t) = F(t,x(t)), x(t₀) = x₀. | S: 54, 60, 47; W: 61, 70, 72 |
| 77 | **Lokal Lipschitz-stetige zeitabhängige Vektorfelder**; Daten aus Band 76 | Um jedes (t₀,x₀) gibt es J × V und L ≥ 0 mit norm(F(t,x) − F(t,y)) ≤ L norm(x − y) für t ∈ J und x,y ∈ V. | S: 76, 67; W: 68, 75 |
| 78 | **Topologische Mannigfaltigkeiten**; topologischer Raum M, festes n ≥ 0 | M ist Hausdorff, besitzt eine abzählbare Basis und ist lokal homöomorph zu offenen Teilmengen von Rⁿ. Hier werden Mannigfaltigkeiten ohne Rand behandelt. | S: 64; W: 54, 60, 21 |
| 79 | **Differenzierbare Mannigfaltigkeiten**; topologische Mannigfaltigkeit M, festes k ≥ 1 oder k = ∞ | M trägt einen maximalen Cᵏ-Atlas; sämtliche Kartenwechsel sind Cᵏ-Diffeomorphismen. | S: 78, 71; W: — |

Band 69 enthält Rolle, Mittelwertsatz und elementare Extremwerttheorie. Band 70 enthält insbesondere Eindeutigkeit der Ableitung und Kettenregel. Die Banachraumvoraussetzungen für Umkehr- und implizite Funktionensätze werden in Band 71 jeweils mitgenannt; sie gehören nicht zur Definition jeder differenzierbaren Abbildung.

Band 72 konstruiert außerdem Logarithmus, Exponentialfunktion und reelle Potenzen, beispielsweise zunächst log(x) als Integral von 1/t und anschließend exp als Umkehrfunktion. Damit stehen aˢ für a > 0 und reelles s vor der Hausdorff-Dimension in Band 102 zur Verfügung.

Band 72 ermöglicht eine frühe Integralrechnung und die koordinatenweise Integration von Kurven in Rⁿ. Das Lebesgue-Integral folgt später in Band 90. Der Vergleich beider Integrale gehört nach Vorliegen des Lebesguemaßes in Band 92. Für allgemeine Banachraum-Differentialgleichungen wäre zusätzlich eine ausdrücklich entwickelte vektorwertige Integration notwendig.

Band 76 behandelt lokale Existenz in endlicher Dimension, insbesondere den Satz von Peano. Die benötigte Version von Arzelà–Ascoli wird dort als Hilfssatz bewiesen, sofern sie aus dem beweisfreien metrischen Leitfaden noch nicht kanonisch vorliegt. Band 77 behandelt Picard–Lindelöf, Eindeutigkeit, maximale Fortsetzung und stetige Abhängigkeit. Die Lipschitzbedingung gilt lokal gleichmäßig in der Zeit; separate Lipschitzbedingungen für jeden festen Zeitpunkt genügen als Planvoraussetzung nicht.

Für autonome Felder wird in Band 77 der lokale Fluss auf den maximalen Existenzintervallen konstruiert. Ein globaler Fluss aus Band 75 entsteht erst nach einem zusätzlichen Nachweis globaler Existenz. Nichtautonome Gleichungen liefern zunächst zweiparametrige Lösungsabbildungen.

## Bände 80 bis 84 Synthetische euklidische Geometrie

| Band | Titel und Grunddaten | Strukturaxiome | Direkte Voraussetzungen |
| --- | --- | --- | --- |
| 80 | **Inzidenzebenen**; Punktmenge P, Geradenmenge L, Inzidenz I ⊆ P × L | Zwei verschiedene Punkte liegen auf genau einer Geraden; jede Gerade enthält mindestens zwei verschiedene Punkte; es existieren drei nichtkollineare Punkte. | S: 03; W: 05 |
| 81 | **Geordnete Inzidenzebenen**; Inzidenzebene mit Zwischenrelation B | Zwischenliegen erzwingt Kollinearität und Verschiedenheit; Umkehrsymmetrie; Verlängerbarkeit einer Strecke; genau einer von drei verschiedenen kollinearen Punkten liegt zwischen den anderen; Pasch-Axiom. | S: 80; W: 15 |
| 82 | **Neutrale Ebenen**; geordnete Inzidenzebene mit Strecken- und Winkelkongruenz | Kongruenzäquivalenzen, eindeutige Streckenübertragung, Segmentaddition, eindeutige Winkelübertragung auf vorgegebener Seite und SWS-Kongruenz. Die Präzisierungen unten sind Teil dieses Axiomkerns. | S: 81; W: 11 |
| 83 | **Euklidische Hilbert-Ebenen**; neutrale Ebene | Playfair: Durch einen Punkt außerhalb einer Geraden gibt es höchstens eine zu ihr parallele Gerade. Die Existenz einer Parallelen wird schon in der neutralen Theorie bewiesen. | S: 82; W: — |
| 84 | **Dedekind-vollständige euklidische Ebenen**; euklidische Hilbert-Ebene | Jede Gerade ist bezüglich einer mit dem Zwischenliegen verträglichen Orientierung Dedekind-vollständig: jede nichtleere nach oben beschränkte Punktmenge besitzt ein Supremum auf dieser Geraden. | S: 83; W: 13, 15, 19, 58 |

Für Band 81 werden die Bedingungen folgendermaßen festgelegt. Aus B(A,B,C) folgen drei verschiedene kollineare Punkte und B(C,B,A). Zu A ≠ B existiert C mit B(A,B,C). Unter drei verschiedenen Punkten einer Geraden gibt es genau einen mittleren. Pasch besagt: Eine Gerade, die keinen Eckpunkt eines nichtausgearteten Dreiecks enthält und eine offene Seite trifft, trifft auch eine der beiden anderen offenen Seiten. Strahlen und die beiden Seiten einer Geraden werden danach definiert.

Für Band 82 wird Streckenkongruenz zunächst auf nichtausgearteten ungerichteten Strecken definiert. Winkel werden als ungeordnete Paare verschiedener, nicht entgegengesetzter Strahlen mit gemeinsamem Anfangspunkt behandelt. Beide Kongruenzen sind Äquivalenzrelationen. Jede nichtausgeartete Strecke lässt sich von einem vorgegebenen Anfangspunkt auf einem vorgegebenen Strahl eindeutig abtragen. Für B(A,B,C) und B(A′,B′,C′) folgt aus AB ≅ A′B′ und BC ≅ B′C′ die Kongruenz AC ≅ A′C′. Ein vorgegebener Winkel lässt sich an einem Strahl auf einer vorgegebenen Seite seiner Geraden eindeutig abtragen. Stimmen zwei Seiten und ihr eingeschlossener Winkel zweier nichtausgearteter Dreiecke überein, stimmen alle entsprechenden Seiten und Winkel überein.

Diese gewählte Ebenenaxiomatik folgt der Gliederung in Inzidenz, Anordnung, Kongruenz, Parallelen und Kontinuität. Die neutrale Ebene enthält hier ausdrücklich weder Parallelen- noch Kontinuitätsaxiom. Die Axiomgruppen sind bei [Francis, Axiomatic Systems for Geometry](https://gkfweb.math.illinois.edu/public402/axiomaticmethod/axioms/postulates.pdf) und die Ebenenfassung bei [Donaldson, Euclidean Geometry](https://webapps.math.uci.edu/~ndonalds/math161/2euclid.pdf) dargestellt.

Die Verbindung von Band 84 zur zweidimensionalen reellen euklidischen affinen Ebene aus Band 58 ist ein Koordinatisierungssatz. Eine Einheitsstrecke und ein geeignetes Koordinatensystem legen dabei die numerischen Koordinaten fest; sie sind keine zusätzlichen Grundaxiome jeder Ebene. Bloße Archimedizität wird nicht mit Dedekind-Vollständigkeit gleichgesetzt.

## Bände 85 bis 95 Mengenstrukturen und Maße

| Band | Titel und Grunddaten | Strukturaxiome | Direkte Voraussetzungen |
| --- | --- | --- | --- |
| 85 | **Boolesche Algebren**; Verband (B,∧,∨) mit 0,1 und Komplementoperation ¬ | 0 ist kleinstes, 1 größtes Element; beide Distributivgesetze; a ∧ ¬a = 0 und a ∨ ¬a = 1. Die einelementige Algebra ist zugelassen. | S: 45; W: — |
| 86 | **Mengenringe**; Menge X mit R ⊆ P(X) | ∅ ∈ R; A,B ∈ R impliziert A ∪ B ∈ R und A \ B ∈ R. X selbst muss nicht in R liegen. | S: 03; W: — |
| 87 | **Mengenalgebren**; Mengenring (X,R) | X ∈ R. Damit sind relative Komplemente und endliche Vereinigungen zugelassen. | S: 86; W: 85 |
| 88 | **Messbare Räume**; Mengenalgebra (X,Σ) | Für jede Folge (Aₙ) in Σ liegt auch deren Vereinigung in Σ. Σ ist damit eine σ-Algebra. | S: 87; W: 21, 63 |
| 89 | **Messbare Abbildungen**; messbare Räume (X,Σ),(Y,T), f: X → Y | Für jedes B ∈ T liegt f⁻¹[B] in Σ. | S: 88; W: — |
| 90 | **Maßräume**; messbarer Raum (X,Σ) mit μ: Σ → [0,∞] | μ(∅) = 0; für jede paarweise disjunkte Folge (Aₙ) gilt μ(⋃Aₙ) = Σ μ(Aₙ). | S: 88; W: 89, 19, 21, 61, 62, 72 |
| 91 | **Prämaßräume**; Mengenring (X,R) mit μ₀: R → [0,∞] | μ₀(∅) = 0; abzählbare Additivität für paarweise disjunkte Aₙ ∈ R, sofern auch ⋃Aₙ wieder in R liegt. | S: 86; W: 90, 47 |
| 92 | **Außenmaßräume**; Menge X mit μ*: P(X) → [0,∞] | μ*(∅) = 0; Monotonie; μ*(⋃Aₙ) ≤ Σ μ*(Aₙ) für jede Folge von Teilmengen. | S: 03; W: 19, 21, 88, 90, 91, 72 |
| 93 | **Vollständige Maßräume**; Maßraum (X,Σ,μ) | Ist N ∈ Σ mit μ(N) = 0 und A ⊆ N, dann A ∈ Σ. Aus den Maßaxiomen folgt μ(A) = 0. | S: 90; W: 92 |
| 94 | **σ-endliche Maßräume**; Maßraum (X,Σ,μ) | Es gibt Eₙ ∈ Σ mit X = ⋃Eₙ und μ(Eₙ) < ∞ für alle n. | S: 90; W: 91, 92 |
| 95 | **Endliche Maßräume**; Maßraum (X,Σ,μ) | μ(X) < ∞. Das Nullmaß ist zugelassen. Die σ-Endlichkeit folgt daraus. | S: 90; W: 94 |

Band 85 behandelt abstrakte Boolesche Algebren. Band 87 behandelt ihre konkrete Realisierung als Mengenalgebren; ein allgemeiner Darstellungssatz braucht einen eigenen Nachweis und klar bezeichnete Auswahlvoraussetzungen. Die Mengenringe aus Band 86 werden nicht mit den Ringen mit Eins aus Band 43 verwechselt. Symmetrische Differenz und Durchschnitt liefern eine algebraische Verbindung, keine Gleichsetzung der Signaturen.

Band 88 behandelt erzeugte σ-Algebren, Produkt-σ-Algebren und Borel-σ-Algebren. Die allgemeine Theorie messbarer Abbildungen wird Band 89 zugeordnet. Band 90 führt [0,∞], nichtnegative Reihen, einfache Funktionen und das Lebesgue-Integral auf einem allgemeinen Maßraum ein. Monotone Konvergenz, Fatou und dominierte Konvergenz benötigen dabei keine allgemeine σ-Endlichkeitsannahme.

Band 91 entwickelt Prämaße und insbesondere die Intervalllänge. Band 92 konstruiert Außenmaße aus Überdeckungen, formuliert das Carathéodory-Kriterium und beweist die Maßfortsetzung. Das Lebesguemaß ist das zentrale Modell; hier wird auch der Vergleich mit der Riemannintegration aus Band 72 hergestellt. Die allgemeine Fortsetzungseindeutigkeit unter σ-Endlichkeit wird in Band 94 behandelt.

Band 94 enthält Produktmaße, Tonelli, Fubini und Radon–Nikodým mit ihren jeweiligen Voraussetzungen. Band 95 untersucht die Folgen endlicher Gesamtmasse, Konvergenz in Maß und Normalisierung bei positiver Gesamtmasse. Vollständigkeit, σ-Endlichkeit und Endlichkeit sind getrennte Bedingungen. Diese Trennungen entsprechen dem Aufbau von [Shapiro, Measure Theory](https://web.math.princeton.edu/~js129/PDFs/teaching/MAT425_spring_2025/MAT425_Lecture_Notes.pdf); die Bandgrenzen sind die hier gewählte redaktionelle Aufteilung.

## Bände 96 bis 101 Wahrscheinlichkeit und Statistik

| Band | Titel und Grunddaten | Strukturaxiome | Direkte Voraussetzungen |
| --- | --- | --- | --- |
| 96 | **Wahrscheinlichkeitsräume**; endlicher Maßraum (Ω,F,P) | P(Ω) = 1. Die Vollständigkeit des Maßraums wird nicht vorausgesetzt. | S: 95; W: 89, 94 |
| 97 | **Diskret filtrierte Wahrscheinlichkeitsräume**; Wahrscheinlichkeitsraum mit (Fₙ) für n ∈ N | Jedes Fₙ ist eine σ-Algebra auf Ω; Fₙ ⊆ F; Fₙ ⊆ Fₙ₊₁. | S: 96; W: 21, 94 |
| 98 | **Stochastische Kerne**; messbare Räume (X,Σ),(Y,T), K: X × T → [0,1] | Für jedes x ist K(x,·) ein Wahrscheinlichkeitsmaß; für jedes B ∈ T ist x ↦ K(x,B) messbar. | S: 88, 96; W: 89, 94 |
| 99 | **Statistische Modelle**; messbarer Beobachtungsraum (X,Σ), nichtleere Indexmenge Θ, Familie (Pθ) | Jedes Pθ ist ein Wahrscheinlichkeitsmaß auf demselben (X,Σ). Identifizierbarkeit, endliche Parameterdimension und eine σ-Algebra auf Θ werden nicht allgemein verlangt. | S: 96; W: 89 |
| 100 | **Dominierte statistische Modelle**; statistisches Modell mit gemeinsamem Maß μ | μ ist σ-endlich und Pθ ist für jedes θ absolut stetig bezüglich μ. Die Dichten werden durch Radon–Nikodým gewonnen. | S: 99, 94; W: — |
| 101 | **Statistische Entscheidungsmodelle**; statistisches Modell, nichtleerer messbarer Aktionsraum (A,Aσ), Verlust L: Θ × A → [0,∞] | Für jedes θ ist L(θ,·) messbar. Eine deterministische Entscheidungsregel δ: X → A ist messbar; randomisierte Regeln sind stochastische Kerne. | S: 99, 88; W: 89, 90, 98 |

Band 96 behandelt Zufallsvariablen, Verteilungen, Unabhängigkeit, Erwartungswerte und Grenzwertsätze. Insbesondere wird das abzählbare Produkt endlicher diskreter Wahrscheinlichkeitsräume konstruiert; diese konkrete Produktkonstruktion wird später in Band 106 benötigt. Band 97 entwickelt bedingte Erwartung, Adaptierung, Stoppzeiten und Martingale in diskreter Zeit. Rechtsstetigkeit von Filtrationen ist hier kein Axiom, da der Zeitindex N ist. Band 98 behandelt Komposition, Mischung und Übergangswahrscheinlichkeiten; die Existenz regulärer bedingter Verteilungen wird nicht auf beliebigen messbaren Räumen vorausgesetzt.

Band 99 macht den Übergang von einem gegebenen Wahrscheinlichkeitsgesetz zu einer Familie möglicher Gesetze ausdrücklich. Schätzer und Tests sind besondere messbare Abbildungen. Band 100 entwickelt Likelihood, Suffizienz und Neyman–Pearson mit den nötigen Zusatzbedingungen. Für Dichten auf überabzählbaren Parameterfamilien werden gemeinsame Messbarkeit und Versionswahl bei Bedarf gesondert geprüft.

In Band 101 wird das Risiko als Erwartungswert des Verlustes konstruiert. Bayes-Verfahren benötigen zusätzlich eine messbare Parameterstruktur, einen Prior und geeignete gemeinsame Messbarkeit. Diese Daten gehören nicht automatisch zu jedem statistischen Modell. Zur Trennung von Modell und Entscheidungsstruktur siehe [Berkeley, Statistical Models and Decisions](https://stat210a.berkeley.edu/fall-2025/handwritten/lecture03-estimation.pdf).

## Bände 102 bis 106 Metrik Maß und fraktale Geometrie

| Band | Titel und Grunddaten | Strukturaxiome | Direkte Voraussetzungen |
| --- | --- | --- | --- |
| 102 | **Metrische Außenmaßräume**; metrischer Raum (X,d) mit Außenmaß μ* | Für Teilmengen A,B mit positivem gegenseitigem Abstand gilt μ*(A ∪ B) = μ*(A) + μ*(B). | S: 47, 92; W: 88, 72 |
| 103 | **Metrische Maßräume**; (X,d,Σ,μ) | (X,d) ist metrisch; (X,Σ,μ) ist ein Maßraum; die Borel-σ-Algebra B(X) ist in Σ enthalten. | S: 47, 90; W: 88, 102 |
| 104 | **Kontraktive iterierte Funktionensysteme**; nichtleerer vollständiger metrischer Raum X mit S₁,…,Sₘ, m ≥ 1 | Jedes Sᵢ: X → X ist kontraktiv: Es gibt 0 ≤ qᵢ < 1 mit d(Sᵢx,Sᵢy) ≤ qᵢ d(x,y). | S: 68; W: 20 |
| 105 | **Selbstähnliche iterierte Funktionensysteme**; System aus Band 104 | Für jedes i gibt es 0 < rᵢ < 1 mit d(Sᵢx,Sᵢy) = rᵢ d(x,y). | S: 104; W: 58, 102 |
| 106 | **Gewichtete kontraktive Funktionensysteme**; System aus Band 104 mit Gewichten p₁,…,pₘ | pᵢ > 0 und Σpᵢ = 1. Die Abbildungen müssen keine Ähnlichkeiten sein. | S: 104, 96; W: 98, 103 |

Band 102 konstruiert Hausdorff-Außenmaße und Hausdorff-Dimension und beweist die Messbarkeit der Borel-Mengen. In Band 103 werden lokale Endlichkeit, Regularität und Verdopplungsbedingungen als zusätzliche Hypothesen behandelt; sie gehören nicht zur hier gewählten allgemeinen Definition.

Band 104 konstruiert die Hausdorffmetrik auf den nichtleeren kompakten Teilmengen von X und beweist die Vollständigkeit dieses Raums. Der Hutchinson-Operator A ↦ ⋃Sᵢ[A] ist kontraktiv; sein eindeutiger Fixpunkt ist der kompakte Attraktor. Damit kann dieser Band unmittelbar nach den metrischen Grundlagen und Band 68 ausgearbeitet werden. Die Maßbände mit kleineren Nummern sind keine Voraussetzung.

Für die klassische Dimensionsformel in Band 105 werden m ≥ 2, ein euklidischer Umgebungsraum und die Open-Set-Bedingung ausdrücklich verlangt: Es existiert eine nichtleere offene Menge O mit Sᵢ(O) ⊆ O und paarweise disjunkten Sᵢ(O). Unter diesen Voraussetzungen ergibt die Lösung von Σrᵢˢ = 1 die Hausdorff-Dimension. Bei m = 1 ist der Attraktor ein einzelner Punkt. Ohne geeignete Trennungsbedingungen ist die Dimensionsgleichheit kein allgemeiner Satz.

Band 106 konstruiert das eindeutige invariante Borel-Wahrscheinlichkeitsmaß auf dem kompakten Attraktor. Der Beweis führt über das Bernoulli-Produktmaß auf unendlichen Symbolfolgen aus Band 96 und dessen Bild unter der Kodierungsabbildung; er benötigt keinen Vorgriff auf Daniell-Integration aus Band 108. Es erfüllt μ = Σpᵢ(Sᵢ)₊μ, wobei (Sᵢ)₊μ das Bildmaß bezeichnet. Mengenattraktor, Dimensionsaussage und invariantes Maß haben damit jeweils sichtbare Voraussetzungen. Siehe [Hutchinson, Fractals and Self-Similarity](https://maths-people.anu.edu.au/~john/Assets/Research%20Papers/fractals_self-similarity.pdf).

## Bände 107 und 108 Axiomatischer Integralzugang

| Band | Titel und Grunddaten | Strukturaxiome | Direkte Voraussetzungen |
| --- | --- | --- | --- |
| 107 | **Reelle Vektorverbände**; reeller Vektorraum E mit Halbordnung ≤ | Jede Paarmenge besitzt Infimum und Supremum; x ≤ y impliziert x + z ≤ y + z; für a ≥ 0 impliziert x ≤ y auch ax ≤ ay. | S: 53, 19, 12, 14; W: 45 |
| 108 | **Daniell-Integrationssysteme**; nichtleere Menge X, Vektorunterverband U ⊆ Rˣ, I: U → R | I ist linear und positiv; für fₙ ∈ U mit fₙ punktweise monoton fallend gegen 0 gilt I(fₙ) → 0. | S: 107; W: 21, 90, 92 |

Band 107 behandelt die Verbindung von linearer und Verbandstruktur. In Band 108 wird ein Integral als Teil der Grunddaten axiomatisch vorgegeben und anschließend erweitert. Dies ist ein zweiter Zugang zur Integration, nicht eine zusätzliche Voraussetzung für die Lebesgue-Theorie aus Band 90.

Die konstante Funktion 1 wird nicht allgemein als Element von U gefordert. Maßdarstellungen benötigen die jeweils passenden Zusatzbedingungen, etwa geeignete Abschlusseigenschaften unter Abschneiden. Der Axiomkern entspricht dem etablierten Daniell-Ansatz; siehe [Blackstone und Mikusiński, The Daniell Integral, Definition 2.2](https://arxiv.org/html/1401.0310v2).

## Zuordnung der Oberbegriffe und der Numerik

| Gewünschtes Gebiet | Tragende Bände | Modelle und Verfahren |
| --- | --- | --- |
| Euklidische Geometrie | 55–58 und 80–84 | Affine Koordinaten, Kongruenz, synthetische Beweise und ihre Koordinatisierung |
| Fraktale Geometrie | 68, 102–106 | Cantormenge, Sierpiński-Dreieck, Attraktorapproximation, Dimension, invariante Maße |
| Maßtheorie | 85–95, 102–103 | Lebesguemaß, Produktmaße, Hausdorffmaße |
| Integrationstheorie | 72, 90–94, 107–108 | Riemann- und Lebesgue-Integral, Konvergenzsätze, Daniell-Zugang |
| Wahrscheinlichkeitstheorie | 96–98 | Zufallsvariablen, Prozesse, Übergangskerne, Martingale |
| Statistik | 99–101 | Schätzen, Testen, Likelihood, Entscheidungsregeln und Risiko |
| Differentialrechnung | 69–71, 78–79 | Eindimensionale und Fréchet-Ableitung, lokale Koordinaten, Tangentialräume |
| Gewöhnliche Differentialgleichungen | 73–77 | Peano, Picard–Lindelöf, lokale Lösungsabbildungen, Fortsetzung |
| Numerische lineare Algebra | 54, 57, 60 | Gaußverfahren, orthogonale Zerlegung, Kondition, kleinste Quadrate |
| Nichtlineare Numerik | 68, 70–71 | Fixpunktiteration und Newtonverfahren mit Fehlerabschätzungen |
| Numerische Integration | 72, 90 | Quadraturregeln mit Regularitäts- und Fehlerannahmen |
| Numerik von Differentialgleichungen | 76–77 | Euler- und Runge–Kutta-Verfahren, Konsistenz, Stabilität und Konvergenz |

Numerik erhält in diesem Plan keinen künstlichen allgemeinen Axiomkern. Die Verfahren werden als mathematische Theorie und Begleitfassungen ihrer jeweiligen Strukturklasse ausgearbeitet. Insbesondere wird der Zusammenhang zwischen Kondition des Problems, Stabilität eines Verfahrens und Konvergenz einer Diskretisierung ausdrücklich getrennt.

Auch Lᵖ-Räume werden zunächst als konstruierte Modelle behandelt. Für 1 ≤ p < ∞ werden messbare Funktionen mit endlichem Integral von abs(f)ᵖ, für p = ∞ wesentlich beschränkte messbare Funktionen betrachtet; anschließend wird jeweils nach Gleichheit fast überall quotientiert. Für 1 ≤ p ≤ ∞ sind die resultierenden Räume Banachräume, für p = 2 Hilberträume. Der Aufbau verbindet Band 90 mit Band 60 bis 62; seine Beweise stehen in der Modellergänzung zu Band 90, deren Voraussetzungen die Bände 61, 62 und 72 ausdrücklich mitführen. Die früheren Bände 61 und 62 enthalten dazu zunächst nur einen Ausblick. Vor der Quotientenbildung liegt im Allgemeinen nur eine Seminorm vor.

Partielle Differentialgleichungen, Sobolevräume, komplexe Analysis, Riemannsche Mannigfaltigkeiten sowie weitere unabhängige Logik- und Algebraerweiterungen liegen außerhalb dieses ersten nummerierten Ausbauplans. Für sie müssten weitere Struktur- und Modellklassen eigens geplant werden.

## Empfohlene Arbeitsfolge

Die Nummern sind dauerhafte Orientierungsmarken für diesen Vorschlag. Sie verlangen nicht, dass vor Band 104 bereits alle Bände 49 bis 103 fertiggestellt werden.

| Arbeitsblock | Reihenfolge | Ergebnis |
| --- | --- | --- |
| Gemeinsame algebraische Grundlage | 49 → 50; 52 → 53 → 54 | Allgemeine Körper und lineare Strukturen; Band 51 kann parallel entstehen |
| Frühe euklidische Geometrie | 55 und 56 → 57 → 58 | Punkt- und Vektorgeometrie mit klarer Trennung der Grunddaten |
| Funktionalanalytische Grundlage | 59 → 60 → 61; 56 + 61 → 62 | Normen, Vollständigkeit, Projektionen und Funktionenräume |
| Allgemeine Topologie | 63 → jeweils 64, 65, 66 | Unabhängige Erweiterung der metrischen Begriffe |
| Frühe Analysis | 69 und 70 → 71 → 72 | Differential- und Riemannintegralrechnung; Band 70 setzt die Normraumgrundlage voraus |
| Frühe Fraktale | 47 → 67 → 68 → 104 | Attraktoren und ihre Approximation ohne vorangehende Maßtheorie |
| Maß und Stochastik | 86 → 87 → 88 → 89 → 90 → 91 → 92; danach 93 beziehungsweise 94 → 95 → 96 | Messbarkeit, Integral, Maßkonstruktion und Wahrscheinlichkeit; Band 85 liefert die abstrakte Boolesche Verbindung |
| Statistik | 96 → 99 → 100 und 101; 98 für Randomisierung | Modelle, Dichten und Entscheidungsregeln |
| Differentialgleichungen | 72 + 68 → 76 → 77; 73–75 als Dynamikzweig | Existenz, Eindeutigkeit, Fortsetzung und numerische Begleitfassungen |
| Synthetische Geometrie | 80 → 81 → 82 → 83 → 84 | Geometrische Axiomgruppen und Verbindung zum reellen Ebenenmodell |
| Vertiefungen | 78 → 79; 102 → 103; 104 → 105 und 106; 107 → 108 | Mannigfaltigkeiten, geometrische Maße, gewichtete Systeme und Daniell-Integration |

Die Tabellen zu den einzelnen Bänden bleiben für die vollständigen direkten Voraussetzungen maßgeblich. Die Arbeitsfolge zeigt die Hauptwege und lässt gemeinsame Grundlagen aus Platzgründen weg.

## Einheitlicher Aufbau eines neuen Fachbands

Jeder neue Fachband beginnt mit einer Tabelle seiner Grunddaten und übernommenen Strukturprädikate. Danach folgen die zusätzlichen Axiome, mindestens ein Modell, ein Gegenbeispiel zur Abgrenzung, strukturtreue Abbildungen, Unterstrukturen beziehungsweise geeignete Konstruktionen und die zentralen Sätze. Bei Abbildungsklassen treten Komposition, Einschränkung und gegebenenfalls Invertierbarkeit an die Stelle einer pauschalen Unterstrukturtheorie.

Für den Überblicksband werden die neuen Bedingungen den wichtigsten Folgerungen gegenübergestellt. Ein Strukturaxiom, eine bewiesene Existenzbehauptung und ein nur als Ziel vorgesehener Satz werden getrennt gekennzeichnet. Ausgelagerte Lesefassungen und Beweistabellen benutzen dieselben kanonischen Aussagen und Nummern.

## Quellen im Hauptprojekt

- [Bandverzeichnis](../VOLUMES.md)
- [Band 19 Reelle Zahlen](../Bd.%2019%20-%20Reelle%20Zahlen.tex)
- [Band 47 Metrische Räume und Vollständigkeit](../Bd.%2047%20-%20Metrische%20Räume%20und%20Vollständigkeit.tex)
- [Beweisfreier Leitfaden zu Band 47](../editions/b47-main-results.tex)
- [Fixpunkttheorie im Leitfaden](../tex/b47/main-results/06-completion-fixed-points.tex)
- [Hausdorffmetrik im Leitfaden](../tex/b47/main-results/08-hausdorff.tex)

Der ältere [Ausbauvorschlag zu Gödels Unvollständigkeitssätzen](goedel-ausbau.md) bildet einen eigenen Zweig. Vor einer gemeinsamen Nummerierung müssen seine inzwischen mit Band 48 überlappenden Teile abgeglichen werden.
