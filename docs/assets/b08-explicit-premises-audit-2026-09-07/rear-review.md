# B08-Prämissenprüfung: hinterer Abschnitt

Geprüft von `audit_b15_b27`: ab „Induzierte Potenzmengenabbildung“ bis Dateiende. Erfasst wurden sämtliche 45 Haupttheoreme, 35 registrierten Hilfsteile, die zugehörigen Delta-Kontexte und die 1033 Beweiszeilen im Bereich. Ergebnis der sachlichen Prämissenprüfung: **45 Haupttheoreme ok, 35 Hilfsteile ok, keine notwendige Änderung**. Es wurden keine Quellen geändert und keine Builds gestartet.

„ok“ bedeutet hier: Für die mathematische Aussage ist keine zusätzliche sachliche Voraussetzung aus Delta, Prosa oder einem undischargierten Beweisfall in die Sequenz zu übernehmen. Es bedeutet keine erneute Zertifizierung jeder einzelnen Regelabkürzung des gesamten Altbestands. Nummern und Zeilen beziehen sich auf den bei der Prüfung vorliegenden Stand; die enthaltenen IDs und vollständigen Strukturformeln bleiben die stabileren Suchanker.

## Abgrenzungen

- Im Bereich gibt es keine sachliche `DeltaPrem`-Zeile. Die Delta-Angaben nennen Mengen, Funktionen, Hilfsvariablen oder bereits definierte Terme. Funktionszuordnungen, Bijektivität, Disjunktheit, Frische, Teilmengenbedingungen und Nulltreue stehen, soweit benötigt, bereits in den Sequenzprämissen.
- Bei den eingeschränkten Potenzmengenabbildungen ist C eine beliebige Menge. Eine zusätzliche Prämisse C⊆P(A) oder C⊆P(B) wäre unnötig: Es werden die Differenzen mit C und die Elementbedingungen verwendet.
- Die Aussagen über Kernfamilien verlangen nicht pauschal P∩A=∅. Die Disjunktheit erscheint ausdrücklich dort, wo der Kerntransport sie voraussetzt. Ebenso benötigen die reine Schichttypisierung und die Mengenzerlegung keine Disjunktheit; die festen Schichtanteile und die Bijektionssätze nennen ihre jeweiligen Disjunktheiten ausdrücklich.
- In `ProtectedPowerSetExtension` sind die Hilfsnamen O und eta sogar durch ausdrücklich mitgeführte Gleichungsprämissen gebunden. Es gibt hier keine stillschweigende Wahl einer beliebigen Abbildung.
- `SurjectiveBranchWitnessTransfer` enthält die Zweiggleichheit ausdrücklich als Subbeweisprämisse `[u∈A]⋮G(u)=f(u)` in der Anzeige. Das ist keine versteckte Zusatzannahme.
- Im Vertauschungsbeweis ist t(y) ausdrücklich als der verschachtelte `IfThenElse`-Term definiert. Die drei registrierten `TranspositionTerm...`-Hilfsteile verwenden diese lokale syntaktische Abkürzung; eine zusätzliche Annahme über eine beliebige Funktion t wäre sachlich falsch. Insbesondere b≠c ist nicht nötig: der Beweis behandelt auch b=c.
- Die Existenzannahmen in Zeugen- und Fallteilen werden für die jeweilige Zielaussage entladen. Ein bloßer solcher lokaler Beweisschritt ist daher kein Anlass, seine Aussage als neue Hauptprämisse aufzunehmen.

## Vollständige Haupttheoremliste

| Nr. | Zeile | ID bzw. Titel bei strukturellem Schlüssel | Status | Begründung |
| --- | ---: | --- | --- | --- |
| 8.3.5.1 | 1449 | Injektivität der induzierten Potenzmengenabbildung | ok | Bijektivität, beide Potenzmengenzugehörigkeiten und Bildgleichheit ausdrücklich genannt. |
| 8.3.5.2 | 1491 | Surjektivität der induzierten Potenzmengenabbildung | ok | Bijektivität und Zielteilmenge ausdrücklich genannt; Urbild liegt daraus im Quellträger. |
| 8.3.5.3 | 1515 | Induzierte Potenzmengenabbildung einer Bijektion | ok | Bijektivität der Grundabbildung liefert sämtliche verwendeten Funktions- und Bildeigenschaften. |
| 8.3.5.4 | 1559 | PowerMapInjectivityPointwiseReflection | ok | Grundtyp, Injektivität der induzierten Abbildung, beide Quellelemente und Wertgleichheit ausdrücklich genannt. |
| 8.3.5.5 | 1625 | PowerMapInjectiveReflectsInjectivity | ok | Grundtyp und induzierte Injektivität ausdrücklich genannt; Elemente werden im Injektivitätsquantor gebunden. |
| 8.3.5.6 | 1644 | PowerMapSurjectivityPointwiseReflection | ok | Grundtyp, induzierte Surjektivität und Zielzugehörigkeit ausdrücklich genannt; beide Zeugen sind lokal. |
| 8.3.5.7 | 1698 | PowerMapSurjectiveReflectsSurjectivity | ok | Grundtyp und induzierte Surjektivität ausdrücklich genannt. |
| 8.3.5.8 | 1716 | PowerMapBijectiveReflectsBijectivity | ok | Grundtyp und induzierte Bijektivität ausdrücklich genannt; keine allgemeine Potenzmengen-Kürzungsannahme. |
| 8.3.5.9 | 1774 | NonemptyPowerMapBijective | ok | Bijektivität von f ist genannt; eingeschränkte PowMapNE-Notation ist in B05 definiert. |
| 8.3.5.10 | 1818 | RestrictedPowerMapBijectiveIffCCompatible | ok | Bijektivität von F ist genannt; C darf eine beliebige Menge sein, keine zusätzliche Teilmengenannahme nötig. |
| 8.3.5.11 | 2049 | RestrictedPowerMapInjectivityPointwiseReflection | ok | Grundtyp, Sichtbarkeit der Quelleinermengen, eingeschränkte Injektivität und punktweise Daten ausdrücklich genannt. |
| 8.3.5.12 | 2167 | RestrictedPowerMapInjectiveReflectsInjectivity | ok | Grundtyp, Sichtbarkeit der Quelleinermengen und eingeschränkte Injektivität ausdrücklich genannt. |
| 8.3.5.13 | 2194 | RestrictedPowerMapSurjectivityPointwiseReflection | ok | Grundtyp, Sichtbarkeit der Zieleinermengen, eingeschränkte Surjektivität und Zielzugehörigkeit ausdrücklich genannt. |
| 8.3.5.14 | 2271 | RestrictedPowerMapSurjectiveReflectsSurjectivity | ok | Grundtyp, Sichtbarkeit der Zieleinermengen und eingeschränkte Surjektivität ausdrücklich genannt. |
| 8.3.5.15 | 2297 | RestrictedPowerMapBijectiveReflectsBijectivity | ok | Beide verschiedenen Einermengenbedingungen, Grundtyp und eingeschränkte Bijektivität ausdrücklich genannt. |
| 8.3.6.1 | 2456 | CaseFunBijectiveDisjointTargets | ok | Disjunktheit beider Quell-/Zielzweige und beide Zweigbijektionen ausdrücklich genannt. |
| 8.3.6.2 | 2665 | CoreFamilyBooleanInterval | ok | Unbedingte Definitionsgleichheit zweier wohldefinierter Mengenfamilien; P⊆P∪A gilt stets. |
| 8.3.6.3 | 2684 | CoreFamilyMembership | ok | Unbedingtes Elementkriterium der definierten Kernfamilie; keine Disjunktheit nötig. |
| 8.3.6.4 | 2705 | CoreFamilySubsetPowerset | ok | Unbedingte Folgerung aus dem Elementkriterium; keine Disjunktheit nötig. |
| 8.3.6.5 | 2721 | CoreFamilyAdjoinedSplit | ok | Frische c∉P∪A ausdrücklich genannt; P und A selbst dürfen sich überschneiden. |
| 8.3.6.6 | 2889 | CoreTransportTarget | ok | Alle deklarierten Disjunktheits-, Typ- und Elementprämissen genannt; der Zielmengennachweis setzt nichts Weiteres voraus. |
| 8.3.6.7 | 2959 | CoreTransportValue | ok | Beide Aussagen nennen die Voraussetzungen von CoreTransportDef; die Wertgleichung nennt zusätzlich H im Definitionsbereich. |
| 8.3.6.8 | 3012 | CoreFamilyRemainder | ok | Disjunktheit und Familienzugehörigkeit ausdrücklich genannt; Disjunktheit ist hier sogar stärker als nötig. |
| 8.3.6.9 | 3039 | CoreTransportRoundTrip | ok | Beide Disjunktheiten, beide Funktionsrichtungen, linke Umkehrgleichung und H-Zugehörigkeit ausdrücklich genannt. |
| 8.3.6.10 | 3105 | CoreFamilyTransportBijective | ok | Beide Disjunktheiten und Bijektivität ausdrücklich genannt; sämtliche Eigenschaften der Umkehrfunktion werden daraus gewonnen. |
| 8.3.6.11 | 3246 | CoreFamilyAbsorptionBijective | ok | Frische, beide Disjunktheiten, zwei Bijektionen und Disjunktheit der Zielfamilien ausdrücklich genannt. |
| 8.3.6.12 | 3344 | ProtectedPowerSetExtension | ok | Alle Schutz-, Typ- und Frischebedingungen sowie die Gleichungen für O und eta ausdrücklich genannt. |
| 8.3.6.13 | 3598 | LayerPowerMapTarget | ok | Typ von g und X-Zugehörigkeit ausdrücklich genannt; zusätzliche Schichtdisjunktheit ist für die Typisierung unnötig. |
| 8.3.6.14 | 3649 | LayerPowerMapValue | ok | Die Typisierungsprämisse der Definition ist in beiden Aussagen genannt; die zweite nennt zusätzlich X im Definitionsbereich. |
| 8.3.6.15 | 3699 | LayerSetDecomposition | ok | X⊆A∪D ist über Potenzmengenzugehörigkeit ausdrücklich genannt; die Zerlegung erfordert keine Disjunktheit. |
| 8.3.6.16 | 3717 | LayerPowerMapStablePart | ok | Die benötigte Disjunktheit A∩E=∅, Typ von g und X-Zugehörigkeit ausdrücklich genannt; A∩D=∅ ist hierfür unnötig. |
| 8.3.6.17 | 3768 | LayerPowerMapComponent | ok | Die benötigte Disjunktheit A∩E=∅, Typ von g und X-Zugehörigkeit ausdrücklich genannt. |
| 8.3.6.18 | 3817 | LayerPowerMapRoundTrip | ok | Beide Disjunktheiten, g/h-Typen, linke Umkehrgleichung und X-Zugehörigkeit ausdrücklich genannt. |
| 8.3.6.19 | 3874 | LayerPowerMapBijective | ok | Beide Disjunktheiten und Bijektivität von g ausdrücklich genannt; Umkehrdaten werden abgeleitet. |
| 8.3.6.20 | 4022 | LayerPowerMapFixesStableUnion | ok | g-Typ, X-Zugehörigkeit und Fixierung der variablen Komponente ausdrücklich genannt. |
| 8.3.6.21 | 4047 | LayerPowerMapFixesStableSubsets | ok | Quellschichtdisjunktheit, g-Typ, Nulltreue, L⊆A und X⊆L ausdrücklich genannt. |
| 8.3.6.22 | 4078 | LayerPowerMapPreservesSubsets | ok | Beide Disjunktheiten, Bijektivität, Nulltreue, L⊆A und X-Zugehörigkeit ausdrücklich genannt. |
| 8.3.6.23 | 4206 | FixedEmptyBijectionNonemptyPreimage | ok | Bijektivität auf vollen Potenzmengen und Fixierung der leeren Menge ausdrücklich genannt. |
| 8.3.6.24 | 4324 | LayerPowerMapNonemptyBijective | ok | Beide Disjunktheiten, Bijektivität von g und Fixierung der leeren Menge ausdrücklich genannt. |
| 8.3.7.1 | 4388 | FreshExtMapOnBase | ok | Zielinklusion, Typ von F, Frische von a, c-Zielzugehörigkeit und alte x-Zugehörigkeit ausdrücklich genannt. |
| 8.3.7.2 | 4418 | FreshExtMapAtNew | ok | Zielinklusion, Typ von F, Frische von a und c-Zielzugehörigkeit ausdrücklich genannt. |
| 8.3.7.3 | 4439 | FreshExtMapBijective | ok | Bijektivität und Frische beider neuen Elemente ausdrücklich genannt; notwendige Zielinklusionen sind allgemeine Mengensätze. |
| 8.3.8.1 | 4851 | TranspositionBijectionExists | ok | Beide Trägerzugehörigkeiten ausdrücklich genannt; b≠c wird nicht vorausgesetzt und im Beweis nicht benötigt. |
| 8.3.8.2 | 5064 | PointedBijectionExists | ok | Existenz einer Ausgangsbijektion und beide ausgezeichneten Elementzugehörigkeiten ausdrücklich genannt; Zeugen werden entladen. |
| 8.3.9.1 | 5097 | Leere Relation ist bijektiv auf $\varnothing$ | ok | Unbedingter Satz über die leere Relation; die leeren Injektivitäts-/Surjektivitätsbedingungen sind bereits bewiesen. |

## Vollständige Liste der registrierten Hilfsteile

| Nr. | Zeile | ID bzw. Titel | Status |
| --- | ---: | --- | --- |
| 8.3.5.1(H1) | 1457 | Hilfsschritt \(F[X]=F[Y]\) | ok |
| 8.3.5.10(H1) | 1836 | RestrictedPowerMapBijectiveImpliesCCompatibility | ok |
| 8.3.5.10(H2) | 1913 | CCompatibilityImpliesRestrictedPowerMapBijective | ok |
| 8.3.6.1(H1) | 2471 | SurjectiveBranchWitnessTransfer | ok |
| 8.3.6.1(H2) | 2504 | CaseFunBijectiveBranchesCommonCodomain | ok |
| 8.3.6.1(H3) | 2540 | CaseFunBijectiveDisjointTargetsSurjectivity | ok |
| 8.3.6.5(H1) | 2735 | CoreFamilyAdjoinedSplitCover | ok |
| 8.3.6.5(H2) | 2851 | CoreFamilyAdjoinedSplitDisjoint | ok |
| 8.3.6.7(H1) | 2973 | CoreTransportMapping | ok |
| 8.3.6.7(H2) | 2990 | CoreTransportEvaluation | ok |
| 8.3.6.10(H1) | 3118 | CoreFamilyTransportInjective | ok |
| 8.3.6.10(H2) | 3174 | CoreFamilyTransportSurjective | ok |
| 8.3.6.12(H1) | 3370 | ProtectedPowerSetExtensionBijective | ok |
| 8.3.6.12(H2) | 3469 | ProtectedPowerSetExtensionFixesOutside | ok |
| 8.3.6.12(H3) | 3548 | ProtectedPowerSetExtensionFixesEmpty | ok |
| 8.3.6.14(H1) | 3663 | LayerPowerMapMapping | ok |
| 8.3.6.14(H2) | 3678 | LayerPowerMapEvaluation | ok |
| 8.3.6.19(H1) | 3887 | LayerPowerMapInjective | ok |
| 8.3.6.19(H2) | 3945 | LayerPowerMapSurjective | ok |
| 8.3.6.22(H1) | 4093 | LayerPowerMapPreservesSubsetsForward | ok |
| 8.3.6.22(H2) | 4118 | LayerPowerMapPreservesSubsetsBackward | ok |
| 8.3.6.23(H1) | 4214 | FixedEmptyBijectionNonemptyPreimageForward | ok |
| 8.3.6.23(H2) | 4254 | FixedEmptyBijectionNonemptyPreimageBackward | ok |
| 8.3.7.3(H1) | 4450 | FreshExtMapInjectiveCaseAA | ok |
| 8.3.7.3(H2) | 4490 | FreshExtMapInjectiveCaseAN | ok |
| 8.3.7.3(H3) | 4534 | FreshExtMapInjectiveCaseA | ok |
| 8.3.7.3(H4) | 4568 | FreshExtMapInjectiveCaseN | ok |
| 8.3.7.3(H5) | 4607 | FreshExtMapInjectivePointwise | ok |
| 8.3.7.3(H6) | 4639 | FreshExtMapInjective | ok |
| 8.3.7.3(H7) | 4700 | FreshExtMapSurjectiveOldValue | ok |
| 8.3.7.3(H8) | 4741 | FreshExtMapSurjectiveNewValue | ok |
| 8.3.7.3(H9) | 4774 | FreshExtMapSurjective | ok |
| 8.3.8.1(H1) | 4863 | TranspositionTermExists | ok |
| 8.3.8.1(H2) | 4910 | TranspositionTermValues | ok |
| 8.3.8.1(H3) | 4969 | TranspositionTermBijective | ok |

Die maschinenlesbare Fassung `rear-review.json` enthält jede vollständige Anzeige, Originalstruktur (soweit separat vorhanden), Delta-Zeilen, Identifikation und Einzelbewertung. `rear-source-inventory.json` und `rear-helper-inventory.json` bewahren das ursprüngliche reine Inventar. Für diesen Bereich gibt es deshalb keine vorgeschlagene neue Formel, Beweisänderung oder ID-Migration.
