# Nächste Schritte zur Vereinfachung der Beweise

Stand: 11. September 2026. Grundlage ist der aktuelle Arbeitsstand der 48 Fachbände einschließlich der eingebundenen Dateien von Band 28 und 48, nicht der ältere Git-Stand. Die Durchsicht verbindet eine Strukturinventur mit gezielter Prüfung wiederkehrender Beweisfamilien. Sie ist keine vollständige erneute Korrektheitsprüfung aller Beweise. Die Manuskriptdateien wurden dabei nicht geändert.

**Hauptempfehlung: Zuerst den allgemeinen Abstieg einer Funktion entlang einer Surjektion beweisen.** Danach die lokalen Quotientenkonstruktionen in Band 17/18 und 41/43 darauf zurückführen. Das bündelt dieselbe Arbeit an mehreren weit auseinanderliegenden Stellen. Als kleiner Probelauf eignen sich die Paarmengenregeln oder das einseitige Erkennen von Inversen.

## 1. Allgemeiner Quotientenabstieg: der größte gemeinsame Ansatz

**Einfügen:** In [Band 07 vor „Leere Bereiche“](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 07 - Surjektive Funktionen.tex:1607>), nach den Kompositionssätzen, einen Abschnitt „Faktorisierung entlang einer Surjektion“ ergänzen.

Für Mengen A, Q, B lautet der neue Satz:

\[
\begin{gathered}
q:A\twoheadrightarrow Q,\qquad h:A\to B,\\
\forall a,a'\in A\;(q(a)=q(a')\Rightarrow h(a)=h(a'))\\
\Longrightarrow\quad
\exists!\bar h:Q\to B\;(\bar h\circ q=h).
\end{gathered}
\]

In Worten: Haben Vertreter desselben Objekts immer denselben h-Wert, so definiert h eindeutig eine Funktion auf den dargestellten Objekten. Vorgeschlagener neuer Schlüssel: `SurjectionFactorization`.

Der Beweis konstruiert den Graphen

\[
\{(u,b)\in Q\times B\mid
   \exists a\in A\;(q(a)=u\land h(a)=b)\}.
\]

Surjektivität liefert die Existenz eines Wertes, Faserverträglichkeit seine Eindeutigkeit. `UniqueValuedGraphFunction` ([Band 05:1692](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 05 - Funktionen.tex:1692>)) und `FunctionExtensionality` ([Band 05:569](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 05 - Funktionen.tex:569>)) liefern Funktion und Eindeutigkeit. Dafür ist kein Auswahlaxiom nötig: Es wird keine globale Vertreterauswahl vorgenommen.

**Direkt mitliefern:** eine punktweise Fassung mit einem eindeutig bestimmten Wert pro Faser und eine binäre Fassung für h auf A×A. Für die binäre Fassung entweder die Surjektivität von q×q einmal beweisen oder den Graphen unmittelbar mit zwei Repräsentanten konstruieren. Die punktweisen Fassungen passen zu den bereits vorhandenen Aussagen und vermeiden unnötige Änderungen ihrer Schnittstellen.

**In Band 11 ergänzen:** Vor [„Quotientenbildabbildung einer Teilfamilie“](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 11 - Äquivalenzrelationen.tex:1430>) ein kurzes Korollar für Äquivalenzrelationen einfügen. `QuotProjSurjective` und `QuotProjEqualIffRel` stehen bereits davor. Vorgeschlagene Schlüssel: `QuotientFunctionDescent`, `QuotientBinaryOperationDescent`.

**Diese Beweise anschließend umstellen:**

| Band / Quellstelle | Bestehender Schlüssel | Was lokal bleibt |
| --- | --- | --- |
| [17:766](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 17 - Ganze Zahlen.tex:766>) | `IntegerNegationQuotientDescent` | Träger und Verträglichkeit der Negation |
| [17:1064](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 17 - Ganze Zahlen.tex:1064>) | `IntegerAdditionQuotientDescent` | Abschluss und Verträglichkeit der Paaraddition |
| [17:1880](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 17 - Ganze Zahlen.tex:1880>) | `IntegerMultiplicationQuotientDescent` | Abschluss und Verträglichkeit der Paarmultiplikation |
| [18:748](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 18 - Rationale Zahlen.tex:748>) | `RationalNegationQuotientDescent` | Verträglichkeit der Bruchnegation |
| [18:1015](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 18 - Rationale Zahlen.tex:1015>) | `RationalAdditionQuotientDescent` | Nennerbedingungen und Verträglichkeit |
| [18:1314](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 18 - Rationale Zahlen.tex:1314>) | `RationalMultiplicationQuotientDescent` | Nennerbedingungen und Verträglichkeit |
| [18:2304](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 18 - Rationale Zahlen.tex:2304>) | `RationalReciprocalQuotientDescent` | Einschränkung auf Nichtnullklassen und Verträglichkeit |
| [41:873](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 41 - Abelsche Gruppen.tex:873>) | `GroupCompletionOperationQuotientDescent` | `GroupCompletionOperationCompatible` und Trägernachweis |
| [43:1312](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 43 - Ringe mit Eins.tex:1312>) | `IntegerRingMapQuotientDescent` | `IntegerRingPairValueCarrier`, `IntegerRingMapRepresentativeIndependent` |

Diese neun Zielbeweise enthalten zusammen 382 explizite Tabellenzeilen: 249 in Band 17/18, 41 in Band 41 und 92 in Band 43. Das ist der Umfang der betroffenen Beweise, **keine behauptete Nettoersparnis**. Die allgemeinen Sätze kosten zunächst eigene Beweise; Typisierung und Verträglichkeit bleiben auch nach der Umstellung erforderlich. Der bereits kurze `RationalOrderQuotientDescent` ist hierbei nicht mitgezählt.

**Beispiel Band 43:** Setze P=ℕ×ℕ, q(a,b)=[a,b] und h(a,b)=v_R(a,b). Statt erneut einen Graphen, eindeutige Werte, Funktionalität und Eindeutigkeit zu beweisen, sind vier Aufgaben zu erledigen: q als Surjektion ausweisen, h als Funktion typisieren, die vorhandene Repräsentantenunabhängigkeit anwenden und den allgemeinen Satz instanziieren. Diese vier Aufgaben sind ein Beweisplan, keine bereits fertige Vierzeilentabelle.

## 2. Band 03 um zwei kleine Werkzeuge ergänzen

### Aussonderungen durch ihre Prädikate vergleichen

**Einfügen:** Nach `SeparationEqualityPredicateEquivalence`, [Band 03:904](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 03 - Mengenlehre.tex:904>). Der vorhandene Satz geht von gleichen Mengen zur Äquivalenz der Prädikate. Die umgekehrte Richtung ergänzen:

\[
\forall x\in A\;(P(x)\leftrightarrow Q(x))
\Longrightarrow \{x\in A\mid P(x)\}=\{x\in A\mid Q(x)\}.
\]

Dazu die praktische Variante mit S⊆A und P(x)↔x∈S, deren Ergebnis direkt {x∈A | P(x)}=S lautet. Vorgeschlagene Schlüssel: `SeparationEqualityFromPointwiseIff`, `SeparationEqualsSubsetFromPointwiseIff`. Eine Monotoniefassung mit P→Q kann später folgen.

**Umstellen:**

- [Band 03:2532](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 03 - Mengenlehre.tex:2532>): Gleichheit der Aussonderungen mit x∈{a} beziehungsweise x=a; derzeit 15 Schritte für zwei Inklusionen.
- [Band 05:1324](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 05 - Funktionen.tex:1324>): `PreimageEqFromPointwiseIff`; derzeit 33 Tabellenzeilen, obwohl die punktweise Charakterisierung bereits Voraussetzung ist.
- [Band 13:859](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 13 - Schranken, Infima und Suprema.tex:859>) und [13:935](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 13 - Schranken, Infima und Suprema.tex:935>): `DualLowerBoundsAreUpperBounds`, `DualUpperBoundsAreLowerBounds`; jeweils 28 Schritte. Die Äquivalenz der Schrankenprädikate beweisen, dann den Mengengleichheitssatz zitieren. Die vorhandene Ordnungsdualität selbst braucht keinen neuen Beweis.

### Quantoren über Ein- und Zweiermengen auswerten

**Einfügen:** [Band 03:2609](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 03 - Mengenlehre.tex:2609>), nach dem bestehenden einseitigen Existenzsatz über Paarmengen:

\[
\forall z\in\{a,b\}\,P(z)\ \leftrightarrow\ P(a)\land P(b).
\]

Als getrennte Einführungs- und Auswertungsfassung nutzbar machen; anschließend die Existenz- und Einermengenfassungen vervollständigen. Vorgeschlagener Schlüssel: `BoundedForallPair`. Die Regel benötigt a≠b nicht.

**Umstellen:** `PairUpperBoundSetCharacterization` ([Band 13:244](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 13 - Schranken, Infima und Suprema.tex:244>)) und `PairLowerBoundSetCharacterization` ([13:293](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 13 - Schranken, Infima und Suprema.tex:293>)), derzeit je 24 Schritte. Außerdem `TotalOrderPairMinimumExistence` ([Band 15:224](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 15 - Totale Ordnungen.tex:224>)) und `TotalOrderPairMaximumExistence` ([15:282](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 15 - Totale Ordnungen.tex:282>)), derzeit je 28 Schritte.

Beispiel: Im Minimumsbeweis unter x≤y genügen x≤x und x≤y für ∀u∈{x,y}:x≤u. Die innere Fallunterscheidung u=x oder u=y entfällt. Die äußere Fallunterscheidung x≤y oder y≤x bleibt.

## 3. Vorhandene Sätze aus Band 28 in den späteren Bänden nutzen

Die Beweise zu neutralen Elementen und Einheiten wurden bereits ausgebaut. Hier ist vor allem die Wiederverwendung nachzuholen.

**Vorhanden:** In [tex/B28-isomorphism-examples.tex:2578](<C:/Latex/Die-Grundlagen-der-Mathematik/tex/B28-isomorphism-examples.tex:2578>) stehen `SemigroupUnitsAtIdentityDef`, `SemigroupIsoIdentityZeroConditions`, `SemigroupUnitCarrierStructure` und `SemigroupIsoIdentitiesZerosUnits`. Die letzten drei werden bisher nur innerhalb dieser Beispieldatei verwendet.

**Einfügen:** Nach `MonoidUnitDef`, vor [Band 38:1001](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 38 - Monoide.tex:1001>), unter der Monoidvoraussetzung die Brücke „u ist Monoideinheit genau dann, wenn u∈U(A,e)“ beweisen. Nach `MonoidUnitSetDef` bei [Band 40:1133](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 40 - Gruppen.tex:1133>) die entsprechende Trägergleichheit A^×=U(A,e) ergänzen.

**Umstellen:**

- `SemigroupIsoMonoidTransport`, [Band 38:1679](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 38 - Monoide.tex:1679>): Neutralität aus dem bereits vorhandenen Isomorphietransport übernehmen.
- `SemigroupIsoBetweenMonoidsUnits`, [Band 38:1796](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 38 - Monoide.tex:1796>): Einheiten über die Notationsbrücke transportieren.
- `MonoidUnitSetProduct`, [Band 40:1246](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 40 - Gruppen.tex:1246>): Abschluss aus `SemigroupUnitCarrierStructure`; die erneute Konstruktion mit Inversenzeugen entfällt.
- `MonoidUnitSetIsGroup`, [Band 40:1334](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 40 - Gruppen.tex:1334>): Halbgruppenanteil übernehmen, Neutralität und Inversenexistenz für den Gruppenanteil ergänzen.

Die Brücken gehören in Band 38/40. Die früheren Aussagen in Band 28 müssen weiterhin ohne spätere Monoid- und Gruppenbegriffe auskommen.

## 4. Schnittkonstruktionen in Band 19 über eine gemeinsame untere Hülle aufbauen

**Einfügen:** Nach `RealCutMembership`, vor [„Hauptschnitte“, Band 19:242](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 19 - Reelle Zahlen.tex:242>), die strikte untere Hülle

\[
D(S)=\{q\in\mathbb Q\mid\exists s\in S\;(q<s)\}
\]

definieren und beweisen: Ist ∅≠S⊆ℚ nach oben durch eine rationale Zahl beschränkt, dann ist D(S) ein Dedekindschnitt. Die rationale Dichte liefert das Fehlen eines größten Elements; Transitivität liefert Abwärtsabgeschlossenheit. Nichtleere und Echtheit werden ebenfalls einmal allgemein bewiesen.

Den bereits vorhandenen Hilfssatz `RealCutMemberBelowExterior` ([Band 19:2574](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 19 - Reelle Zahlen.tex:2574>)) an diese frühe Stelle vorziehen. Sein Beweis braucht nur Schnittcharakterisierung und rationale Ordnung. Er ist kein neu zu erfindender Satz.

**Anwendungen:**

| Bestehender Beweis | Erzeugende Menge S |
| --- | --- |
| `RealPrincipalCutIsCut`, [19:254](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 19 - Reelle Zahlen.tex:254>) | {r} |
| `RealCutAdditionIsCut`, [19:1667](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 19 - Reelle Zahlen.tex:1667>) | {a+b : a∈A, b∈B} |
| `RealCutNegationIsCut`, [19:1750](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 19 - Reelle Zahlen.tex:1750>) | {−r : r∈ℚ, r∉A} |
| `RealCutPositiveProductIsCut`, [19:2744](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 19 - Reelle Zahlen.tex:2744>) | {0}∪{ab : a∈A, b∈B, a>0, b>0} |
| `RealCutPositiveReciprocalIsCut`, [19:2977](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 19 - Reelle Zahlen.tex:2977>) | {0}∪{1/r : r∈ℚ, r>0, r∉A} |

Die Nichtleere und obere Beschränktheit von S sowie die Gleichheit mit der jeweils definierten Schnittoperation sind lokal nachzuweisen. Bei Produkt und Reziprokem erzeugt das beigefügte {0} genau die negative rationale Halbachse. Dadurch werden auch die Nullfälle erfasst.

Der Gewinn betrifft zunächst die Abschlussbeweise. Die in den bisherigen Prüfberichten benannten fehlenden Zeugenargumente für Distributivität oder inverse Produktgesetze werden dadurch nicht automatisch bewiesen.

## 5. Pfadabschnitte durch eine Indexabbildung statt wiederholter Induktion

**Einfügen in Band 10:** Nach `PeanoNatSegShiftMembership`, vor [Band 10:13346](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 10 - Natürliche Zahlen.tex:13346>), die Verschiebungsabbildung j↦k+j auf den passenden endlichen Anfangssegmenten als Injektion mit Anfangs-, End- und Schrittauswertung bereitstellen. Die arithmetischen Typisierungs- und Kürzungsresultate sind bereits vorhanden.

**Einfügen in Band 26:** Nach `FinitePathPowerSetTyping`, vor [Band 26:406](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 26 - Bäume.tex:406>), einen allgemeinen Abschnittssatz: Für einen Weg p der Länge n und k+ℓ≤n ist q(j)=p(k+j), 0≤j≤ℓ, ein Weg mit den entsprechenden Endpunkten. Bei einem einfachen Weg bleibt q injektiv, weil beide beteiligten Abbildungen injektiv sind. Für die Komposition muss die Verschiebung in den ursprünglichen Indexbereich von p typisiert werden; gegebenenfalls die Inklusion des kürzeren Anfangssegments mitkomponieren.

**Umstellen:**

- `FiniteWalkInitialSegment`, [26:406](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 26 - Bäume.tex:406>): Spezialfall k=0.
- `FinitePathTailSegment`, [26:568](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 26 - Bäume.tex:568>): Spezialfall k=1; derzeit 68 Tabellenzeilen.
- `FinitePathFinalSegment`, [26:1799](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 26 - Bäume.tex:1799>): ℓ mit k+ℓ=n wählen. Die eigenen Suffix-Induktionsbausteine bei 1572 und 1624 werden für diesen Beweis überflüssig.

Dies ist ein Werkzeug für spätere Wegkonstruktionen. Die noch offenen Kreis- und Eindeutigkeitsargumente sind anschließend weiterhin mathematisch auszuführen. Kein Rückverweis auf die erst in Band 27 entwickelten Wörter ist nötig.

## 6. Inverse durch nur eine Gleichung erkennen

**Einfügen:** Nach `GroupInverseLeft`, vor [„Kürzungsgesetze“, Band 40:339](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 40 - Gruppen.tex:339>), die beiden Kriterien

\[
x,y\in G,\quad yx=e\Longrightarrow y=x^{-1},
\qquad
x,y\in G,\quad xy=e\Longrightarrow y=x^{-1}
\]

unter expliziter Gruppenvoraussetzung beweisen. Grundlage sind bereits `GroupInverseUnique`, `GroupInverseCarrier`, `GroupInverseRight` und `GroupInverseLeft`.

**Umstellen:** `GroupProductInverse` ([40:590](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 40 - Gruppen.tex:590>)), `RingLeftNegativeProduct` ([43:367](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 43 - Ringe mit Eins.tex:367>)) und `RingRightNegativeProduct` ([43:456](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 43 - Ringe mit Eins.tex:456>)).

Beispiel im Ring: Für c=(−a)b genügt c+ab=((−a)+a)b=0b=0, danach das additive Inversenkriterium. Die nötigen Trägerprämissen bleiben ausdrücklich stehen.

Die internen Teilresultate `GroupProductInverseRightCandidate`, `RingLeftNegativeRightInverse` und `RingRightNegativeRightInverse` werden derzeit außerhalb ihrer Definition nicht zitiert; auch der jeweilige Schlussteil benutzt nur die andere Kandidatengleichung. Zusammen enthalten sie 32 Tabellenzeilen. Nach Prüfung der gewünschten Darstellung können diese redundanten Teilbeweise entfallen. Die drei Hauptaussagen und ihre Schlüssel bleiben erhalten.

## Weitere sinnvolle Ergänzungen nach diesen Schritten

- **Bildkalkül in Band 05:** Nach den Bildgrundregeln bei 784 den Satz „punktweise gleiche Funktionen haben auf derselben Teilmenge gleiches Bild“ ergänzen, auch für verschiedene Definitionsbereiche. Vor `LeftInverseImages` bei 3660 den Kompositionsbildsatz (G∘F)[K]=G[F[K]] bereitstellen. Konkrete Ziele: „Bild der Einschränkung“ bei 2834 und `LeftInverseImages` bei 3660. Im jetzigen Einschränkungsbeweis ist außerdem die Zeugenentladung in beiden Richtungen ausdrücklich nachzuholen.
- **Übertragung von Strukturgesetzen in Band 28:** Nach den ersten Halbgruppengesetzen bei 140 Assoziativität entlang einer operationserhaltenden Surjektion übertragen beziehungsweise entlang einer operationserhaltenden Injektion reflektieren. Anwendungen: `FiniteSemigroupMultiplicationTableTransport` in Band 37:1142, `FiniteSemigroupRelabellingAction` in 37:1284 und `GroupCompletionOperationAssociative` in 41:1312. In der Voraussetzung nur die Abbildung, ihre Eigenschaften, den Abschluss und die Operationsgleichung verlangen. `SemigroupHom` wäre hier zirkulär, weil es die erst zu beweisenden Halbgruppenstrukturen schon voraussetzt.

## Eine logische Präzisierung vor breiter Anwendung von Ersetzungsregeln

[Band 01:1771](<C:/Latex/Die-Grundlagen-der-Mathematik/Bd. 01 - Grundlagen der Logik.tex:1771>), `rule:LRSubst`, sollte die Nebenbedingungen für bindende Formelkontexte ausdrücklich nennen. Aus einer nur punktweise unter offenen Annahmen vorliegenden Äquivalenz P(x)↔Q(x) darf keine Ersetzung unter einem x-bindenden Quantor folgen.

Gegenbeispiel zur uneingeschränkten Lesart: Auf {0,1} gelte P überall und Q nur bei 0; die aktuelle Belegung sei x=0. Dann gelten P(x)↔Q(x) und ∀x P(x), aber nicht ∀x Q(x). Für Ersetzungen unter Bindern ist daher eine entsprechend allgemeine Äquivalenz beziehungsweise die passende Eigenvariablenbedingung nötig. Die vorgeschlagenen Aussonderungssätze verlangen deshalb ausdrücklich die beschränkte Allquantifizierung.

Die bereits vorhandenen iterierten Gleichheits-, Konjunktions- und Existenzregeln sowie die Kettennotation müssen nicht nochmals eingeführt werden. Auch die Korrektheit in Band 48 ist kein Ersatz für die konkrete Ableitung neuer Hilfssätze: `B48DerivationSoundness` behandelt elementare Herleitungen mit bereits aufgelösten Abkürzungen.

## Empfohlene Reihenfolge der Umsetzung

1. Allgemeinen Surjektionsabstieg samt punktweiser und binärer Fassung in Band 07 beweisen; Quotientenkorollare in Band 11 ergänzen.
2. `IntegerAdditionQuotientDescent` in Band 17 als Pilot umstellen. Den vorhandenen Verträglichkeitssatz und die bestehenden Hauptschlüssel beibehalten.
3. Erst nach Prüfung dieses Piloten die übrigen sechs Wert-Abstiege in Band 17/18 und die beiden Anwendungen in Band 41/43 umstellen.
4. Paarmengen- und Aussonderungssätze in Band 03 ergänzen; die oben benannten Beweise in Band 03/05/13/15 verkürzen.
5. Die bereits fertigen Einheiten- und Transportsätze aus Band 28 anbinden; danach die gemeinsamen Schnitt- und Pfadkonstruktionen angehen.

Falls zunächst eine sehr kleine Änderung gewünscht ist, mit dem Inversenkriterium oder den vier Paarmengen-Anwendungen beginnen. Bei jeder Umstellung referenzierte Hilfsteil-Schlüssel erhalten oder ihre Verbraucher gezielt anpassen. Anschließend die betroffenen Einzelbände, Abhängigkeiten und Verweise prüfen und die geänderten Tabellen visuell kontrollieren. Ein erfolgreicher LaTeX-Lauf ersetzt dabei nicht die Prüfung der Voraussetzungen und Annahmenentladungen.
