# Kritische Strukturprüfung der Bände 28–44

Stand: 13.09.2026. Nur Quellen- und Registerprüfung; keine Manuskriptänderung und kein Build. Die Nummern und IDs stammen aus den aktuellen Registern. Zeilen beziehen sich auf die aktuellen Quellen; sie bezeichnen den Satzanfang oder seine unmittelbar anschließende Deklaration.

## Ergebnis und Prioritäten

Die stärksten Kandidaten sind keine beliebigen Kürzungen einzelner Beweise, sondern erkennbare Fehlplatzierungen: reine Mengenlehre in B28/B38, Arithmetik und schon vorhandene Kardinalitätsaussagen in B37, Monoidtheorie in B40 und additive Gruppenrechnung in B43. Daneben gibt es zwei größere Kapitel, deren jetziger Standort die Stoffhierarchie unnötig belastet: die Rechtecksbandkoordinaten in B28 und die Rekonstruktion aller endlichen Bänder im Rechtecksbandband B31.

**Priorität 1** bedeutet: klar allgemeinerer Satz bzw. direkte Wiederholung eines früheren Resultats. **Priorität 2** bezeichnet ein sinnvolles zusammenhängendes Umordnen oder eine Vereinfachung der Satzarchitektur. **Priorität 3** ist eine optionale Verallgemeinerung, deren Nutzen die zusätzliche Begriffsschicht rechtfertigen müsste.

## Abdeckung

Geprüft wurden die Hauptsatzregister aller 17 Bände, die aktiven Quellen einschließlich des einzigen zusätzlichen aktiven Mathematikmoduls `tex/B28-isomorphism-examples.tex` und die Beweise der unten genannten Kandidaten. Das gemeinsame Inventar enthält hier 418 Hauptsätze in 18 Quellen. Das ist eine Strukturprüfung; es behauptet keine vollständige Zeilenprüfung jedes Algebra-Beweises. Versteckte Hilfssätze in Teilbeweisen wurden bei den betroffenen Clustern mit einbezogen.

| Band | Hauptsätze im gemeinsamen Inventar | Aktive Dateien | Struktureller Befund |
|---|---:|---:|---|
| 28 Halbgruppen | 175 | 2 | Mengen-/Funktionshilfen, endliches Mengenprodukt, vorgezogene Rechtecksbandkoordinaten; ansonsten allgemeine Halbgruppentheorie richtig platziert. |
| 29 Kommutative Halbgruppen | 4 | 1 | Passender Zielort für den kommutativen Kreuzproduktvergleich aus B41. Eigene Vertauschungsgesetze passen. |
| 30 Idempotente Halbgruppen | 1 | 1 | Der Vereinigungsbeispielsatz passt; die spätere Rekonstruktion allgemeiner endlicher Bänder betrifft diesen Gegenstand, benötigt aber spätere Hilfsmittel. |
| 31 Rechtecksbänder | 5 | 1 | Koordinatensatz passt; großer Schlussteil behandelt dagegen alle endlichen Bänder. |
| 32 Kommutative idempotente Halbgruppen | 1 | 1 | Vereinigungsbeispiel ist eine sinnvolle Zusammenführung der zuvor eingeführten Struktureigenschaften. |
| 33 Halbgruppen mit Nullelement | 3 | 1 | Nulleindeutigkeit braucht keine Assoziativität; optionale Verallgemeinerung. |
| 34 Linkskürzbare Halbgruppen | 2 | 1 | Natürliche Addition als Beispiel passend; kein klarer zusätzlicher Verlagerungskandidat. |
| 35 Rechtskürzbare Halbgruppen | 5 | 1 | Übergang von Links- zu Rechtskürzung braucht nur Kommutativität, nicht die volle Halbgruppenstruktur. |
| 36 Kürzbare Halbgruppen | 2 | 1 | Die Zusammenführung beider Kürzbarkeiten gehört hierher. |
| 37 Endliche Halbgruppen | 36 | 1 | Kardinalitätsduplikat, reine Arithmetik, allgemeine Permutationen und allgemeine periodische Potenzrechnung. |
| 38 Monoide | 40 | 1 | Reine Einermengenhilfe; überstarke Neutralitätsprämisse; natürlicher Zielort der Monoid-Einheiten aus B40. |
| 39 Halbringe | 37 | 1 | Mehrere große Spezialisierungsblöcke bereits vorhandener Mengen-/Rekursionssätze; reine Arithmetik am Ende. |
| 40 Gruppen | 38 | 1 | Inverseneindeutigkeit gilt schon im Monoid; Einheitenmenge/Produktinverse benötigen ebenfalls nur Monoide. |
| 41 Abelsche Gruppen | 29 | 1 | Zielort additiver Ringhilfen; ein Kreuzproduktvergleich braucht nur kommutative Halbgruppen. Gruppenvervollständigung insgesamt richtig platziert. |
| 42 Endliche Gruppen | 5 | 1 | Erster Rekonstruktionssatz setzt keine Endlichkeit voraus; die Faserzählung danach benötigt sie tatsächlich. |
| 43 Ringe mit Eins | 34 | 1 | Doppelnegation, negative Summe, Differenzenaddition und Kreuzsummenrechnung sind Gruppenresultate. Multiplikative Vorzeichen-/Distributivgesetze bleiben hier. |
| 44 Kommutative Ringe mit Eins | 1 | 1 | Strukturdefinitionen und Ganzzahlbeispiel passend; kein klarer Verlagerungskandidat. |

## Priorität 1: klare allgemeine Vorstufen und Duplikate

### A1. Nichtleere Potenzmengen und Einermengen zurück nach B03

| Aktueller Satz | ID | Quelle |
|---|---|---|
| 28.2.14.5 „Nichtleerheit des Potenzträgers“ | `NonemptyPowerCarrierNonempty` | `Bd. 28 - Halbgruppen.tex`:6692 |
| 38.2.3.1 „Einermengen im nichtleeren Potenzträger“ | `MonoidPowerSingletonCarrier` | `Bd. 38 - Monoide.tex`:239 |

Beide Aussagen sind bereits ohne Algebra formuliert: `A≠∅ ⇒ P₊(A)≠∅` und `a∈A ⇒ {a}∈P₊(A)`. Ziel ist B03 unmittelbar bei **3.16.3.1 `NonemptyPowersetMembership`**. Benötigt werden nur `A⊆A`, die Teilmengeneigenschaft einer Einermenge und Nichtleerheit durch einen Zeugen. Keine Begriffe aus B28/B38 müssen mitgenommen werden. Insbesondere sollte die zweite ID langfristig keinen Monoidbezug mehr tragen.

### A2. Das endliche Mengenprodukt ist ein allgemeiner Satz über endliche Bilder

**28.2.15.11 „Mengenprodukte endlicher Teilmengen sind endlich“**, ID `SemigroupFiniteSetProduct`, `tex/B28-isomorphism-examples.tex`:988; mit den Hilfssätzen `SemigroupFiniteSetProductBase` und `SemigroupFiniteSetProductStep` um :998 und :1010.

Aktuell: Halbgruppe `(A,⋆)`, endliche `X,Y⊆A` ⇒ `{x⋆y | x∈X,y∈Y}` endlich. Im gesamten Beweis wird keine Assoziativität verwendet; die Operation muss lediglich für jedes Paar einen Wert liefern. Sinnvolle allgemeine Form in B20:

`f:X×Y→Z, Finite(X), Finite(Y) ⇒ Finite(f[X×Y])`.

Alternativ mit bereits festem `f:A×B→C` und endlichen Teilmengen `X⊆A,Y⊆B`. Der vorhandene Beweis lässt sich unmittelbar verallgemeinern: Induktion über `X`, im Schritt ist die neue Wertemenge das Bild von `Y` unter `y↦f(a,y)`, danach endliche Vereinigung. Die bereits früheren Bausteine sind **20.3.1.2 `FiniteImage`**, **20.3.5.1 `FiniteUnion`** und die Funktionskonstruktion aus B05. Man darf nicht ohne Prüfung einen schon vorhandenen Satz „endliches kartesisches Produkt“ voraussetzen; die jetzige Induktion liefert die allgemeine Bildfassung auch direkt. In B28 bleibt nur die Anwendung auf den Operatorgraphen von `⋆` und anschließend die Halbgruppenstruktur der endlichen nichtleeren Teilmengen.

### A3. Die Anzahl nichtleerer Teilmengen steht bereits vollständig in B20

**37.2.3.2 „Anzahl der nichtleeren Teilmengen“**, ID `FiniteSemigroupNonemptyPowerSetCardinality`, `Bd. 37 - Endliche Halbgruppen.tex`:139.

Der Satz hat keinerlei Halbgruppenprämisse. Sein fünfzeiliger Beweis ruft **20.3.8.19 `FiniteNonemptyPowerSetCardinality`** auf und projiziert nur die zweite Konjunktion `card(P₊(A))=2^N−1`. Deshalb keine neue Verlagerung nötig: In B37 genügt eine Anwendung bzw. erläuternde Folgerung mit Verweis auf B20. Die Rechnung `3↦7` ist als Motivation einer Potenzhalbgruppentafel sinnvoll und sollte dort bleiben.

### A4. Der geeignete Exponent ist reine natürliche Arithmetik

**37.3.2.6 „Ein geeignetes Periodenvielfaches ist positiv und liegt ab dem Index“**, ID `FiniteSemigroupIdempotentExponentData`, `Bd. 37 - Endliche Halbgruppen.tex`:866.

Aussage: `μ,λ∈N`, beide ungleich null ⇒ `λμ∈N`, `λμ≠0`, `μ≤λμ`. Ziel B10 bei positiven Produkten und Multiplikationsordnung. Sachlicher Titel etwa „Ein positives Vielfaches ist mindestens so groß wie sein Faktor“. Der Beweis benötigt nur **10.4.7.1 `PeanoMulClosure`**, **10.4.10.3 `PeanoMulNonzero`**, Nachfolgerdarstellung einer positiven natürlichen Zahl, Distributivität und die additive Charakterisierung von `≤`. Der jetzige Beweis erwähnt weder Halbgruppen noch Potenzen. In B37 ist „Exponentendaten“ lediglich die Anwendung dieses Satzes.

### A5. Eindeutigkeit eines Inversen braucht nur ein Monoid

**40.2.3.1 „Eindeutigkeit aus Links- und Rechtsinverse“**, ID `GroupInverseUnique`, `Bd. 40 - Gruppen.tex`:186; dazu die drei Hilfsteile `GroupInverseUniqueRightInverseSubstitution`, `GroupInverseUniqueLeftInverseReduction`, `GroupInverseUniqueConclusion`.

Die Gruppenprämisse ist zu stark. Allgemein gilt bereits:

`Monoid(A,⋆,e), x,y,z∈A, y⋆x=e, x⋆z=e ⇒ y=z`.

Beweis: `y=y⋆e=y⋆(x⋆z)=(y⋆x)⋆z=e⋆z=z`. Alle Voraussetzungen liegen in B38 vor: Halbgruppenassoziativität und links-/rechtsneutrales Element. Die Existenz von Inversen für andere Elemente wird nicht benutzt. Diesen Grundsatz in B38 vor den Einheiten platzieren; B40 kann damit die eindeutige Inversenabbildung definieren. Das verhindert, dass ein allgemeines Monoidargument erst als Gruppensatz verfügbar wird.

### A6. Einheitenmenge und Produktinverse aus B40 nach B38

| Aktueller Satz | ID | Quelle in `Bd. 40 - Gruppen.tex` |
|---|---|---:|
| 40.3.3.5 „Inverse bleiben in der Einheitenmenge“ | `MonoidUnitSetInverse` | 1138 |
| 40.3.3.6 „Inverse eines Produkts im Monoid“ | `MonoidInversePairProduct` | 1174 |
| 40.3.3.7 „Produktabschluss der Einheitenmenge“ | `MonoidUnitSetProduct` | 1246 |
| 40.3.3.8 „Träger und Nichtleerheit der Einheitenmenge“ | `MonoidUnitSetCarrier` | 1302 |

Mitnehmen: Definition **40.3.3.1 `MonoidUnitSetDef`**, Quelle :1131, `A×={u∈A | u ist Einheit}`. Die vier Sätze haben bereits ausschließlich Monoidprämissen. Die geprüften Beweise brauchen `MonoidUnitDef` aus **38.2.5.1**, `MonoidIdentityIsUnit` aus **38.2.5.2**, Neutralitätsgesetze, Assoziativität und elementare Mengenlehre. Es gibt hier keinen Rückgriff auf eine notwendige Gruppenkonstruktion.

Die allgemeine Produktinversenformel lautet: Sind `u'` und `v'` beidseitige Inverse von `u` bzw. `v`, dann ist `v'⋆u'` ein beidseitiges Inverses von `u⋆v`. Sie sollte vor **40.2.5.1 `GroupProductInverse`** stehen; dieser Gruppensatz wird dann zur unmittelbaren Anwendung der Monoidformel plus Eindeutigkeit aus A5. **40.3.3.9 „Die Einheiten bilden eine Gruppe“ bleibt in B40**, weil erst dort der Gruppenbegriff vorliegt.

### A7. Additive Ringhilfen auf Gruppenebene formulieren

| Aktueller Satz | ID | Quelle in `Bd. 43 - Ringe mit Eins.tex` | Passender Zielband |
|---|---|---:|---|
| 43.2.3.4 „Doppelte Negation“ | `RingDoubleNegative` | 223 | B40, Inverseninvolution in jeder Gruppe |
| 43.2.5.4 „Additives Inverses einer Summe“ | `RingNegativeSum` | 572 | B41, additive Fassung für abelsche Gruppen |
| 43.2.5.5 „Addition zweier Differenzen“ | `RingDifferenceAddition` | 630 | B41 |
| 43.5.1 „Kreuzsummen liefern gleiche Differenzen im Ring“ | `RingCrossSumGivesDifferenceEquality` | 1086 | B41 |

Allgemeine Aussagen: `(a⁻¹)⁻¹=a`; in additiver abelscher Schreibweise `−(p+q)=−p−q`, `(p−q)+(r−s)=(p+r)−(q+s)` und `p+s=q+r ⇒ p−q=r−s`. Letzteres kann sinnvoll gleich als Äquivalenz formuliert werden. Die geprüften Beweise verwenden nur den additiven Gruppenanteil, **40.2.3.1 `GroupInverseUnique`**, Gruppenneutralität/Assoziativität und die Vertauschungsgesetze **29.2.1.1–2**. Multiplikation, Eins und Distributivität kommen nicht zum Einsatz.

Für die negative Summe steht der stärkere nichtkommutative Grundsatz **40.2.5.1 `GroupProductInverse`** schon zur Verfügung; in B41 braucht man nur die Reihenfolge mithilfe der Kommutativität zu vertauschen. Nach der Verallgemeinerung verwendet B43 diese Sätze für seine additive Gruppe. **43.2.5.1–3 und 43.2.5.6** bleiben dagegen Ring-/Distributivitätsresultate: dort ist die zweite Operation mathematisch wesentlich.

### A8. Die rein arithmetischen Hilfssätze am Ende von B39 bündeln

**39.4.5.1–5**, `Bd. 39 - Halbringe.tex`:1971–2066:

- `NaturalOnePlusCommutative`: `n∈N ⇒ 1+n=n+1`.
- `NaturalAdditionNotGroupContradiction`: `∃n∈N:1+n=0 ⇒ ⊥`.
- `NaturalAdditionNotGroup`: `¬∃n∈N:1+n=0`.
- `NaturalRingInverseRequirementAtOne`: Spezialisierung der allgemeinen Inversenforderung auf `1`.
- `NaturalNumbersNotRingConclusion`: Negation dieser allgemeinen Inversenforderung.

Diese fünf Sätze enthalten keine Halbringstruktur. Die ersten drei reduzieren sich auf **10.4.4.5 `PeanoOneInN`**, **10.4.4.42 `PeanoAddCommutative`** und **10.4.4.11 `PeanoAddOneNonzero`**. Ein einziges sinnvoll benanntes Ergebnis in B10, etwa „Eine positive natürliche Zahl besitzt kein additives Inverses“, wäre stärker und klarer als die fünf lokalen Deklarationen. Die Spezialisierung auf `1` ist gewöhnliche Quantorenelimination und braucht keinen eigenen neuen allgemeinen Satz in B02. **39.4.5.6 `NaturalNumbersNotRing` bleibt als abschließende algebraische Einordnung** bestehen; eine spätere Aussage mit dem eigentlichen Ringprädikat gehört erst nach dessen Definition in B43.

## Priorität 2: zusammenhängende Kapitel und Satzfamilien besser einordnen

### B1. Rechtecksbandkoordinaten aus B28 nach B31

**28.2.13.1–16**, Abschnitt „Koordinatenisomorphismen von Halbgruppen“, `Bd. 28 - Halbgruppen.tex`:5472–6073. Mitnehmen wären die fünf zugehörigen Definitionen/Axiome und alle lokalen Hilfsteile. Leit-IDs sind `SemigroupCoordinateCarrierDef`, `SemigroupCoordinateProductDef`, `SemigroupCoordinateMapDef`, `SemigroupCoordinateIsoDef`, `SemigroupCoordinateProductSemigroup`, `SemigroupCoordinateProductIdempotence`, `SemigroupCoordinateProductThreeTermLaw`, `SemigroupCoordinateIsoCriterion` und `SemigroupCoordinateIsoRectangularIdentity`.

Der gebaute Träger ist `(Ae)×(eA)`, sein Produkt lautet `(p,q)·(r,s)=(p,s)`. Das ist genau die spätere Rechtecksbanddarstellung, einschließlich Idempotenz, Dreitermgesetz und Rechtecksidentität. Ziel: B31 vor **31.2.1.4 `RectangularBandProductRepresentation`**. Alle Mengen-, Funktions- und Halbgruppen-/Isomorphiebegriffe sind dort schon verfügbar. Die Verweise auf die konkreten IDs dieses Blocks liegen in B28 innerhalb des Blocks selbst und in B31; nach dem Block verwendet die B28-Hauptdatei keine davon. Die ähnlich benannten `SemigroupCoordinateProductMapsDef/ForwardFacts/InverseFacts` im aktiven Isomorphismusmodul behandeln dagegen allgemeine direkte Produkte und gehören **nicht** automatisch zu dieser Verlagerung.

Die elementare allgemeine Rechnung `(p,q)(r,s)=(p,s)` kann alternativ von Anfang an auf beliebigen `X×Y` formuliert werden. Die Rekonstruktion einer Halbgruppe mittels eines festen `e` wird dann als Spezialanwendung verständlicher.

### B2. Allgemeine endliche Bänder nicht im Rechtecksbandband abschließen

**31.3.4.1 „Endliche idempotente Halbgruppen sind durch ihre Potenzhalbgruppen global bestimmt“**, ID `FiniteIdempotentSemigroupsGloballyDetermined`, `Bd. 31 - Rechtecksbänder.tex`:1210–1223, samt davor entwickeltem Komponenten-/Transportapparat.

Die Aussage betrifft beliebige endliche idempotente Halbgruppen, nicht nur Rechtecksbänder. B30 wäre vom Gegenstand her naheliegend, liegt aber zu früh: Der Beweis benutzt gerade die rechteckigen, Linksnull- und Rechtsnullkomponenten und ihren Transport. Deshalb besser den **zusammenhängenden Rekonstruktionsblock nach B37** verlagern, in dessen Rekonstruktionsteil der Satz bereits verwendet wird. Er muss dort vor seinem ersten lokalen Aufruf stehen. B31 behält die Rechtecksbandstruktur und ihren Koordinatensatz. Ein bloßes Verschieben der letzten Satzdeklaration ohne die vorausgehenden Komponentenargumente wäre unzureichend.

### B3. Ein Gruppenquadrat braucht keine endliche Ausgangshalbgruppe

**42.3.1.1 „Ein Gruppenquadrat wird mitsamt seinen Einermengen rekonstruiert“**, ID `PowerGroupSquareCoreReconstruction`, `Bd. 42 - Endliche Gruppen.tex`:124, mit `PowerGroupSquareCoreMonoidTransport` und den übrigen lokalen Beweisteilen.

Die Voraussetzungen enthalten nur zwei nichtleere Halbgruppen, ein Gruppenquadrat auf der Quellseite und einen Isomorphismus ihrer Potenzhalbgruppen; **keine Endlichkeit**. Die geprüfte erste Beweisstufe nutzt B28-Quadrattransport und **38.2.3.3/5** (Monoidkriterium für Quadrate). Der weitere Gruppenschluss nutzt bereits die allgemeine Gruppenstarrheit aus B40. Ein sinnvoller Zielort ist **am Ende von B40 nach `GroupPowerSemigroupRigidity` (40.3.3.19)**. B42 startet dann mit **42.3.2.1 `FiniteGroupSquareFiberBijections`**, wo Endlichkeit für die Größen-/Faserargumente tatsächlich gebraucht wird. Die allgemeinen und die endlichen Schritte werden so fachlich getrennt.

### B4. Allgemeine Periodenrechnung aus B37 in die Potenztheorie von B28

**37.3.2.1 `FiniteSemigroupPowerEqualityPropagation`** (:712), **37.3.2.2 `FiniteSemigroupSinglePeriodShift`** (:735) und **37.3.2.5 `FiniteSemigroupMultiplePeriodShift`** (:828) setzen bereits nur eine Halbgruppe, `a∈A`, positive natürliche `μ,λ` und `a^(μ+λ)=a^μ` voraus. Endlichkeit ist nicht nötig.

Diese Sätze passen nach dem Additionsgesetz **28.2.6.8 `SemigroupPowerAdditionLaw`**. Inhalt: Eine vorhandene Wiederholung propagiert unter Multiplikation und erzeugt Periodizität ab einem Index. Abhängigkeiten sind nur die Potenzregeln und natürliche Induktion/Arithmetik. **Die Existenz** einer solchen Wiederholung für jedes Element einer endlichen Halbgruppe bleibt in B37. Die in B37 definierten besonderen `IP`-Prädikate müssten nicht nach B28 wandern: Der allgemeine Teil kann mit der einzelnen Gleichung `a^(μ+λ)=a^μ` formuliert bleiben. Entsprechend kann man diese Satznamen vom irreführenden Präfix `FiniteSemigroup` befreien.

### B5. Permutationen und Umbenennen: allgemeiner Kern vor die endlichen Tafeln

Definition `FiniteSemigroupSymmetricSetDef`, `Bd. 37 - Endliche Halbgruppen.tex`:1233, und **37.4.1.4 `FiniteSemigroupSymmetricSetBijection`**, :1256, definieren `Sym(S)={π∈P(S×S) | π:S↔S}` und projizieren die Bijektivität. Das gehört zu den bijektiven Funktionen in B08; die Definition benötigt keinerlei Endlichkeit oder Halbgruppe.

Das zugehörige `Assoc(S)` (`FiniteSemigroupAssociativeOperationsDef`, :1223) und **37.4.1.3 `FiniteSemigroupAssociativeOperationSemigroup`**, :1246, gehören frühestens B28, weil der Halbgruppenbegriff vorkommt. Die Umbenennung `m^π(u,v)=π(m(π⁻¹u,π⁻¹v))` und ihre Kompositionsregel funktionieren auf beliebigen Trägern. Man kann ihren allgemeinen Kern in B28 bei Strukturtransport formulieren. Nummerierte endliche Tafeln, endliche Orbits und kanonische Tafelcodes bleiben in B37. Eine neue Theorie von Gruppenwirkungen ist für diese Umordnung nicht zwingend; die drei Funktionsgleichungen können ohne den erst später definierten Gruppenbegriff bewiesen werden.

### B6. Der Kreuzproduktvergleich aus der Gruppenvervollständigung braucht keine Eins

**41.4.1.4 „Transitiver Kreuzproduktvergleich“**, ID `GroupCompletionPairRelationTransitiveRearrangement`, `Bd. 41 - Abelsche Gruppen.tex`:273.

Aktuelle Voraussetzung ist ein kommutatives Monoid. Verwendet werden nur Kommutativität und die Umordnung von vier Faktoren. Allgemeine Fassung in B29:

`CommutativeSemigroup(M,⋆), a,b,c,d,f,g∈M, a⋆d=b⋆c, c⋆g=d⋆f ⇒ (a⋆g)⋆(c⋆d)=(b⋆f)⋆(c⋆d)`.

Die frühere Vorstufe **29.2.1.2 `CommutativeSemigroupFourTermExchange`** steht bereits bereit; das neutrale Element `e` fällt vollständig weg. Die folgende Transitivität der Differenzenrelation braucht zusätzlich Kürzbarkeit und bleibt in B41. Ebenfalls keine eigene neue Mengenlehre erforderlich für **41.4.1.6 `GroupCompletionPairRepresentative`** (:358): Der Satz ist nur die Anwendung der Produktdarstellung auf den definierten Träger `M×M`; er kann lokal als Typisierungszugriff bestehen oder im Beweis direkt referenziert werden.

### B7. B39: vorhandene allgemeine Sätze als Anwendungen darstellen

| Spezialisierte Familie | Frühere allgemeine Grundlage | Bewertung |
|---|---|---|
| 39.4.2.1 `NaturalSemiringMapSurjectiveIffFullImage`, B39:1404 | **7.2.1.5 `SurjectiveIffImageEqualsCodomain`** | Kein neuer Satzkern: Nach Typisierung der kanonischen Abbildung ein direkter Verweis. |
| 39.4.2.2 `NaturalSemiringMapSurjectiveIffSuccessorInduction`, :1437 | **10.4.3.30 `RecFunSurjectiveIffInductionPrinciple`** | Der allgemeine Rekursionssatz steht schon richtig; Anwendung kann in B39 bleiben. |
| 39.4.3.1–3, insbesondere `NaturalSemiringMapInjectiveIffNoCollision`, :1520–1704 | Injektivitätsdefinition und Typisierung aus B05 | Drei Deklarationen für die Definition einer injektiven Funktion sind unnötig umfangreich. Eine gemeinsame Folgerung genügt. |
| 39.4.3.4 `NaturalSemiringMapInjectivePeanoCriterion`, :1706 | Früherer B10-Satz `m₀∈M, f:M↪M, ∀x∈M f(x)≠m₀ ⇒ RecFun(m₀,f):N↪M`, im Beweis ausdrücklich zitiert | Nicht erneut verlagern; allgemeiner Kern vorhanden. |
| 39.4.3.5 `NaturalSemiringMapNotInjectiveIntoFiniteSemiring`, :1753 | **20.3.7.42 `FiniteNoNatInjection`** | Der Schluss hängt nur von der Endlichkeit des Zielträgers ab; die Halbringstruktur dient lediglich dazu, die konkrete Abbildung zu benennen. Als Anwendung statt eigener allgemeiner Beweisentwicklung. |
| 39.4.4.1–3, insbesondere `NaturalSemiringMapInjectiveSurjectiveIso`, :1832 | Bereits bewiesener Homomorphismus, Bijektivität = Injektivität + Surjektivität, Isomorphismusdefinition | Definitionelle Schlussfamilie, kein Grund für drei getrennte Hauptsätze. |

Alle Aussagen können als hilfreiche Erläuterungen der kanonischen Halbringabbildung bleiben. Ein weiterer Transfer nach B05/B10 wäre hier eine **Doppelung bereits vorhandener Sätze**, keine Verbesserung. Die eigentliche universelle Eigenschaft des natürlichen Halbrings gehört weiterhin B39.

## Priorität 3: schwächere Voraussetzungen und gemeinsame Darstellung

### C1. Neutralitäts-/Null- und Kürzungsargumente ohne Assoziativität

- **38.2.2.1 `MonoidIdentityCandidateEqualsIdentity`**, B38:86: Der aktuelle Beweis benutzt die Prämisse `∀x∈A: x⋆e'=x` überhaupt nicht; die Schlussabhängigkeiten lauten ausdrücklich nur `1,2,3`. Es genügt die Linksneutralität von `e'`, zusammen mit der Rechtsneutralität des vorhandenen `e`. Allgemeiner: Ein linksneutrales und ein rechtsneutrales Element einer binären Operation stimmen überein. Das ist ein möglicher B07-Operatorsatz; am geringsten ist der Eingriff, zunächst die unbenutzte Prämisse in B38 zu streichen.
- **33.2.1.1 `SemigroupZeroUnique`**, B33:89: Die Gleichheit zweier beidseitig absorbierender Elemente folgt aus `z⋆w=z=w`; Assoziativität wird nicht gebraucht. Ein allgemeiner Satz über linke/rechte Absorber wäre in B07 möglich. Die Anwendung als Eindeutigkeit des Nullelements kann in B33 bleiben.
- **35.2.3.1 `CommutativeLeftCancellationImpliesRightCancellation`** (:135) und **35.2.3.2 `CommutativeLeftCancellativeImpliesRightCancellative`** (:166): Nur Kommutativität und Linkskürzung werden benutzt. Die volle kommutative Halbgruppe ist stärker als nötig. Allerdings sind die Kürzbarkeitsprädikate erst in B34/B35 eingeführt: nicht blind nach B07 verschieben. Entweder in B35 schwächer formulieren oder erst bei einer bewussten allgemeinen Operatorgrundlage die Prädikate mitnehmen. **35.2.3.3**, der Schluss auf eine rechtskürzbare *Halbgruppe*, braucht die Halbgruppenstruktur wieder tatsächlich.

### C2. Rechtstranslationen und Mengenoperationen brauchen nur einen binären Operator

**28.2.6.1–3** (`SemigroupRightTranslationFunction`, `SemigroupRightTranslationEvaluation`, `SemigroupPowerSequenceFunction`, B28:1340–1408) brauchen nur eine geschlossene binäre Operation und `a∈A`: `ρ_a(x)=x⋆a`, danach gewöhnliche Rekursion. Auch das Mengenprodukt in **28.2.4.1 `PowerSemigroupProductMembership`** braucht keine Assoziativität. Ein gemeinsamer allgemeiner Kern könnte in B07 (Operatoren/Funktionen) bzw. B21 (Iterationsfolge) liegen; Assoziativität wird erst für Block-/Potenzgesetze wesentlich. Das ist eine größere Begriffsumstellung und hat geringere Priorität als A1–A8. Ein bloßes Ersetzen der Halbgruppenprämisse ohne Anpassung der Definitionen wäre nicht ausreichend.

### C3. Gleichheitskerne statt zwanzig paralleler Green-Beweise

**28.2.11.5–20**, B28 ab :4771, enthält je Reflexivität, Symmetrie, Transitivität und Zusammenfassung für die Green-Relationen `L,R,J,H`. Für `L,R,J` ist die Relation definitionsgemäß Gleichheit der zugeordneten Hauptideale; `H` ist eine Konjunktion zweier solcher Gleichheiten. Ein allgemeiner früher Satz `f:A→B ⇒ (x∼y :⇔ f(x)=f(y)) ist Äquivalenzrelation` und die Stabilität unter Durchschnitt bündeln den logischen Kern.

Ziel wäre B05 nach der Funktionentheorie mit Rückgriff auf die Relationsbegriffe aus B04; für eine termweise formulierte Variante ist auch B04 möglich. **Die Hauptideal-/Teilbarkeitsinterpretationen bleiben in B28.** In dieser Prüfung wurde kein exakt passender bereits registrierter allgemeiner Gleichheitskern-Satz als gesicherter Ersatz identifiziert; deshalb ist das ein Vorschlag für einen neuen allgemeinen Grundsatz, nicht die Behauptung einer vorhandenen Duplikation. Die jetzigen einzelnen Kurzbeweise können didaktisch gewollt sein.

### C4. Komposition von Morphismen über die gemeinsame operationserhaltende Rechnung

Betroffen sind **28.2.12.1 `SemigroupHomComposition`** (B28:5249), **38.2.6.7 `MonoidHomComposition`** (B38:1885), **39.2.3.1 `SemiringHomComposition`** (B39:251), **40.3.2.1 `GroupHomComposition`** (B40:879) und **43.3.3.1 `RingHomComposition`** (B43:925). Der gemeinsame Kern ist stets

`g(f(x⋆y)) = g(f(x)◇f(y)) = g(f(x))△g(f(y))`.

Die allgemeine operationserhaltende Funktionskomposition benötigt keine Assoziativität. Man könnte sie in B07 formulieren; konservativer bleiben Halbgruppenhomomorphismen in B28 die erste algebraische Grundstufe und die späteren Struktursätze verwenden sie operationenweise. Konstantenerhaltung kommt für Monoide/Halbringe/Ringe hinzu, und bei Gruppen folgt sie schon aus der Gruppenstruktur. **Nicht pauschal alle späteren Morphismussätze löschen**: Ihre Zielprädikate unterscheiden sich. Sinnvoll ist ein gemeinsamer Beweiskern mit kurzen strukturspezifischen Folgerungen. Der entsprechende Fall in B45 kann darauf aufbauen, soweit die dortigen Halbverbandshomomorphismen genau die jeweilige binäre Operation erhalten.

## Ergänzung zur laufenden Prüfung von B21

Die spezifischen Mogiljanskaja-Familien aus B21 Kapitel 6 passen als zusammenhängender Vorbereitungsblock direkt zu B28s Unterabschnitt **„Ein unendliches Gegenbeispiel zur Umkehrung“**, Quelle B28:8081. Ein konkreter Platz ist nach der Motivation und vor der ersten Verwendung von `L,D`, `MogiljanskajaAIndexUnique`, `MogiljanskajaBIndexUnique` und `MogiljanskajaLayersDisjoint` (:8092–8101), somit vor `MogiljanskajaPairDef` (:8132).

Die früheren Potenzfolgen in B28 verwenden ab :1375 allgemeine `RecFun`-Sätze aus B10. Das aktive Isomorphismusmodul verwendet allgemeine Familien-/Produktmittel; diese gehören weiterhin B21. Die konkreten Mogiljanskaja-Schichten werden in der B28-Hauptdatei erstmals an der genannten Gegenbeispielstelle gebraucht. Die von der Hauptprüfung bereits identifizierten späteren B37-Verwendungen bleiben nach einem Transfer B21→B28 rückwärtsgerichtet. Ein bloßes Einfügen in den Anhang B28.3 wäre dagegen zu spät für die Definitionen und Beweise in B28.2.16.

## Was bewusst an seinem jetzigen Ort bleiben sollte

1. Die zahlreichen Beispiele, dass Vereinigung oder natürliche Addition eine neu eingeführte algebraische Struktur tragen, sind nicht schon deshalb falsch platziert, weil ihre elementaren Rechengesetze früher bewiesen wurden. Vor Einführung des Strukturprädikats konnten gerade diese Strukturaussagen nicht formuliert werden. Das betrifft insbesondere B29/B30/B32/B34/B35/B36/B44.
2. Der Blocksatz und die Klammerungsunabhängigkeit in B28 benötigen Assoziativität wirklich. Sie sind ein sinnvoller Anschluss an B27 und sollten nicht zurück in die allgemeine Theorie beliebiger binärer Operationen verschoben werden.
3. Die Existenz periodischer Potenzen und idempotenter Potenzen für alle Elemente endlicher Halbgruppen bleibt B37; lediglich die allgemeine Propagation einer schon gegebenen Wiederholung wird vorgezogen.
4. Die Gruppenvervollständigung eines kommutativen kürzbaren Monoids bleibt insgesamt B41. B17 ist ihr konkretes Zahlbeispiel, liegt jedoch logisch vor den abstrakten Gruppenbegriffen; ein Verweis von B17 auf B41 würde den axiomatischen Aufbau umkehren.
5. Dass die Einheiten eines Monoids eine Gruppe bilden, braucht den Gruppenbegriff und bleibt B40. Nur die vorherigen Monoidberechnungen gehören B38.
6. Bei Ringrechnungen mit Multiplikation und Distributivität ist eine Reduktion auf additive Gruppen unzulässig. Die verlagerten additiven Hilfen ersetzen diese Gesetze nicht.

## Empfohlene Reihenfolge für eine spätere Umsetzung

Zuerst A1/A3/A4/A8 als kleine, klar abgegrenzte Mengen-/Arithmetikbereinigung durchführen. Danach den Monoidkern A5/A6 aufbauen und die Gruppen-/Ringfolgerungen A7 daran anschließen. Erst anschließend die großen Blöcke B1/B2/B3 und den Mogiljanskaja-Transfer bewegen, jeweils einschließlich Definitionen, lokalen Hilfssätzen und Außenverweisen. Die optionalen Operatorverallgemeinerungen C1–C4 sollten erst folgen, wenn ihre gemeinsame Begriffsschicht bewusst gewünscht ist; sie sind keine Voraussetzung für die eindeutigen Verbesserungen.
