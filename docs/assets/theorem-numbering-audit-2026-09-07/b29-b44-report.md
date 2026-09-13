# Nummerierung von Theorem-Schlussaussagen – Bände 29–44

## Ergebnis

455 Theorem-Deklarationen vollständig erfasst. Davon wurden 207 breit gefilterte Mehrzeilen-/Kommakandidaten einzeln geprüft; zusätzlich wurden die übrigen Konklusionen mit Kommas, Semikolons oder Abstandsmarkierungen geprüft. Es gibt in diesem Bereich keine fehlende sichtbare Nummerierung einer unabhängigen Schlussfamilie. Daher keine Quelländerungen für diese Teilaufgabe. Bereits vorhandene Änderungen aus der Beweisregel-Korrektur bleiben erhalten.

Die Abgrenzung folgt dem Auftrag: Eine explizite Konjunktion bleibt eine Aussage, ebenso eine Gleichheits- oder Äquivalenzkette. Kommas in Prämissen, Quantor-Variablenlisten, Mengen, Tupeln und Makroargumenten werden nicht als Aufzählung selbständiger Schlüsse behandelt.

## Abdeckung

| Band | Theorem-Deklarationen |
| --- | ---: |
| Bd. 29 - Kommutative Halbgruppen | 4 |
| Bd. 30 - Idempotente Halbgruppen | 1 |
| Bd. 31 - Rechtecksbänder | 5 |
| Bd. 32 - Kommutative idempotente Halbgruppen | 1 |
| Bd. 33 - Halbgruppen mit Nullelement | 3 |
| Bd. 34 - Linkskürzbare Halbgruppen | 2 |
| Bd. 35 - Rechtskürzbare Halbgruppen | 5 |
| Bd. 36 - Kürzbare Halbgruppen | 2 |
| Bd. 37 - Endliche Halbgruppen | 36 |
| Bd. 38 - Monoide | 40 |
| Bd. 39 - Halbringe | 37 |
| Bd. 40 - Gruppen und Ringe | 83 |
| Bd. 41 - Endliche Gruppen | 5 |
| Bd. 42 - Halbverbände und Verbände | 68 |
| Bd. 43 - Frankls Vermutung | 119 |
| Bd. 44 - Metrische Räume und Vollständigkeit | 44 |

Alle 455 Deklarationen verwenden FormulaThmDeltaK (446) oder FormulaThmDelta (9, nur Band 43). Im geprüften Bereich gibt es keine weiteren FormulaThm-Makrovarianten, klassischen theorem-/lemma-/proposition-/corollary-Umgebungen oder eingebundenen Teildateien. Die vorhandenen enumerate-/itemize-Stellen in Band 37 sind Algorithmen, Beispiele, Literaturübersichten oder bereits nummerierte Voraussetzungen einer Folgerung; keine neue Schlussfamilie in einer Theorem-Deklaration. Der Satz „Dann gelten“ in Band 30 steht in einem unnummerierten erläuternden Beispiel, außerhalb einer Theorem-Deklaration.

## Explizit geprüfte Grenzfälle

| Schlüssel | Einordnung |
| --- | --- |
| FiniteSemigroupMonogenicSize | Monogenbeschreibung, Endlichkeit und Mächtigkeit sind explizit konjunktiv verbunden. |
| FiniteSemigroupRelabellingAction | Die Eigenschaften des Umbenennens stehen in einer einzigen Konjunktion. |
| SemigroupIsoBetweenMonoidsIdentityAndUnits | Neutrales Element und Einheitenaussage sind explizit konjunktiv verbunden. |
| NaturalSemiringMonoidStructures | Additive und multiplikative Struktur bilden eine explizite Konjunktion. |
| GroupCompletionEmbeddingTheorem | Gruppen-, Homomorphie- und Injektivitätsaussage sind explizit konjunktiv verbunden. |
| GroupCompletionClassInverse | Zwei Inversengleichungen mit logischem Konjunktionszeichen. |
| IntegerRingMapConstants | Null- und Einheitswert sind explizit konjunktiv verbunden. |
| MetricIdentityConstantContinuous | Zwei Stetigkeitsaussagen mit logischem Konjunktionszeichen. |
| MetricIsometryPreservesStructure | Strukturfolgen bilden eine explizite, teilweise quantifizierte Konjunktion. |

## Schlüssel und Prüfung

Die Makros wurden in tex/impl/formula-envs.tex geprüft. Insbesondere registriert FormulaThmDeltaK neben der ID auch die Displayformel strukturell. Bei erforderlichen Änderungen wäre FormulaThmDeltaKR mit unveränderter Originalstrukturformel zu verwenden; bei DeltaR bliebe der Formelkey unverändert. Da keine Anzeige geändert wurde, bleiben alle IDs und strukturellen Schlüssel unverändert. Keine Beweise, Beweisschritte oder Hilfsteilnummern wurden in dieser Teilaufgabe geändert. Keine Builds gestartet.

Binärer Vergleich aller 16 Dateien mit den für diese Teilaufgabe erzeugten Ausgangskopien: alle unverändert.

## Dateien

- b29-b44-before/: Ausgangskopien aller 16 Bände zu Beginn dieser Teilaufgabe.
- b29-b44-theorems.json: vollständiges strukturiertes Inventar aller 455 Deklarationen mit Display, Titel, Schlüssel und Zeile.
- b29-b44-theorem-candidates.txt: die 207 breiten Kandidaten mit vollständiger Aussage.
- b29-b44-review.json: Entscheidung und Einordnung aller 455 Aussagen.
- b29-b44-report.md: dieser Bericht.

## Vollständiges Entscheidungsinventar

| Band / Zeile | Schlüssel oder Titel | Entscheidung |
| --- | --- | --- |
| 29 / 70 | CommutativeSemigroupThreeTermExchange | unverändert – Einzelstatement |
| 29 / 97 | CommutativeSemigroupFourTermExchange | unverändert – Einzelstatement |
| 29 / 145 | NaturalAdditionCommutativeSemigroup | unverändert – Einzelstatement |
| 29 / 161 | PowerSetUnionCommutativeSemigroup | unverändert – Einzelstatement |
| 30 / 71 | PowerSetUnionIdempotentSemigroup | unverändert – Einzelstatement |
| 31 / 73 | RectangularBandIsIdempotentSemigroup | unverändert – Einzelstatement |
| 31 / 109 | RectangularBandThreeTermLaw | unverändert – Einzelstatement |
| 31 / 145 | RectangularBandThreeTermCharacterization | unverändert – Einzelstatement |
| 31 / 213 | RectangularBandProductRepresentation | unverändert – Einzelstatement |
| 31 / 1211 | FiniteIdempotentSemigroupsGloballyDetermined | unverändert – Einzelstatement |
| 32 / 94 | PowerSetUnionCommutativeIdempotentSemigroup | unverändert – Einzelstatement |
| 33 / 89 | SemigroupZeroUnique | unverändert – Einzelstatement |
| 33 / 114 | NaturalMultiplicationSemigroupWithZero | unverändert – Einzelstatement |
| 33 / 134 | ConstantSemigroupWithZero | unverändert – Einzelstatement |
| 34 / 98 | NaturalAdditionLeftCancellative | unverändert – Einzelstatement |
| 34 / 115 | NaturalAdditionLeftCancellativeSemigroup | unverändert – Einzelstatement |
| 35 / 98 | NaturalAdditionRightCancellative | unverändert – Einzelstatement |
| 35 / 114 | NaturalAdditionRightCancellativeSemigroup | unverändert – Einzelstatement |
| 35 / 135 | CommutativeLeftCancellationImpliesRightCancellation | unverändert – Einzelstatement |
| 35 / 164 | CommutativeLeftCancellativeImpliesRightCancellative | unverändert – Einzelstatement |
| 35 / 185 | CommutativeLeftCancellativeSemigroupImpliesRightCancellativeSemigroup | unverändert – Einzelstatement |
| 36 / 127 | NaturalAdditionCancellative | unverändert – Einzelstatement |
| 36 / 144 | NaturalAdditionCancellativeSemigroup | unverändert – Einzelstatement |
| 37 / 82 | ConstantFinitePairSemigroup | unverändert – Einzelstatement |
| 37 / 111 | FinitePowerSemigroup | unverändert – Einzelstatement |
| 37 / 139 | FiniteSemigroupNonemptyPowerSetCardinality | unverändert – Einzelstatement |
| 37 / 276 | FiniteSemigroupPowerRepetitionExists | unverändert – Einzelstatement |
| 37 / 439 | FiniteSemigroupLeastRepetitionInitialDistinctness | unverändert – Einzelstatement |
| 37 / 478 | FiniteSemigroupLeastRepetitionProducesIndexPeriod | unverändert – Einzelstatement |
| 37 / 535 | FiniteSemigroupIndexPeriodExistence | unverändert – Einzelstatement |
| 37 / 612 | FiniteSemigroupIndexPeriodEndpointUnique | unverändert – Einzelstatement |
| 37 / 637 | FiniteSemigroupIndexPeriodIndexUnique | unverändert – Einzelstatement |
| 37 / 660 | FiniteSemigroupIndexPeriodUniqueness | unverändert – Einzelstatement |
| 37 / 681 | FiniteSemigroupIndexPeriod | unverändert – Einzelstatement |
| 37 / 712 | FiniteSemigroupPowerEqualityPropagation | unverändert – Einzelstatement |
| 37 / 735 | FiniteSemigroupSinglePeriodShift | unverändert – Einzelstatement |
| 37 / 766 | FiniteSemigroupPowerEventuallyPeriodic | unverändert – Einzelstatement |
| 37 / 785 | FiniteSemigroupMonogenicSize | unverändert – Einzelstatement |
| 37 / 828 | FiniteSemigroupMultiplePeriodShift | unverändert – Einzelstatement |
| 37 / 858 | FiniteSemigroupIdempotentExponentData | unverändert – Einzelstatement |
| 37 / 887 | FiniteSemigroupIdempotentPower | unverändert – Einzelstatement |
| 37 / 913 | FiniteSemigroupIdempotentExists | unverändert – Einzelstatement |
| 37 / 953 | FiniteSemigroupLeastIdealExistence | unverändert – Einzelstatement |
| 37 / 987 | FiniteSemigroupLeastIdealUniqueness | unverändert – Einzelstatement |
| 37 / 1007 | FiniteSemigroupLeastIdeal | unverändert – Einzelstatement |
| 37 / 1043 | FiniteSemigroupLeastIdealCharacterization | unverändert – Einzelstatement |
| 37 / 1142 | FiniteSemigroupMultiplicationTableTransport | unverändert – Einzelstatement |
| 37 / 1185 | FiniteSemigroupTableRelabelCriterion | unverändert – Einzelstatement |
| 37 / 1243 | FiniteSemigroupAssociativeOperationSemigroup | unverändert – Einzelstatement |
| 37 / 1256 | FiniteSemigroupSymmetricSetBijection | unverändert – Einzelstatement |
| 37 / 1284 | FiniteSemigroupRelabellingAction | unverändert – Einzelstatement |
| 37 / 1367 | FiniteSemigroupRelabelGraphCharacterization | unverändert – Einzelstatement |
| 37 / 1435 | FiniteSemigroupRelabelOrbitsAreIsomorphismClasses | unverändert – Einzelstatement |
| 37 / 1506 | FiniteSemigroupTableTupleInjective | unverändert – Einzelstatement |
| 37 / 1563 | FiniteSemigroupCanonicalTableCodeComplete | unverändert – Einzelstatement |
| 37 / 2034 | PowerSemigroupSingletonLayerReconstruction | unverändert – Einzelstatement |
| 37 / 2106 | FinitePowerSemigroupReconstructionOrderTwo | unverändert – Einzelstatement |
| 37 / 2317 | FiniteCancellativeSemigroupGroupExistence | unverändert – Einzelstatement |
| 37 / 2470 | FiniteOneSidedCancellativeMonogenicGroups | unverändert – Einzelstatement |
| 38 / 86 | MonoidIdentityCandidateEqualsIdentity | unverändert – Einzelstatement |
| 38 / 111 | MonoidIdentityUnique | unverändert – Einzelstatement |
| 38 / 173 | PowerSemigroupMonoid | unverändert – Einzelstatement |
| 38 / 195 | PowerSemigroupIdentityCharacterization | unverändert – Einzelstatement |
| 38 / 239 | MonoidPowerSingletonCarrier | unverändert – Einzelstatement |
| 38 / 255 | MonoidPowerSingletonProductValue | unverändert – Einzelstatement |
| 38 / 277 | PowerSemigroupSquareMonoidForward | unverändert – Einzelstatement |
| 38 / 339 | PowerSemigroupSquareIdentityActions | unverändert – Einzelstatement |
| 38 / 396 | PowerSemigroupSquareMonoidBackward | unverändert – Einzelstatement |
| 38 / 469 | PowerSemigroupSquareMonoidCriterion | unverändert – Einzelstatement |
| 38 / 513 | MonoidSquareIdentityProductCarrier | unverändert – Einzelstatement |
| 38 / 543 | MonoidSquareCentralIdentity | unverändert – Einzelstatement |
| 38 / 571 | MonoidSquareProductFactorization | unverändert – Einzelstatement |
| 38 / 631 | MonoidSquareRetractionValue | unverändert – Einzelstatement |
| 38 / 656 | MonoidSquareInflationProduct | unverändert – Einzelstatement |
| 38 / 677 | MonoidSquareInflationProperties | unverändert – Einzelstatement |
| 38 / 710 | MonoidSquarePowerFiberElementForward | unverändert – Einzelstatement |
| 38 / 745 | MonoidSquarePowerFiberProductElement | unverändert – Einzelstatement |
| 38 / 785 | MonoidSquarePowerFiberBackward | unverändert – Einzelstatement |
| 38 / 839 | MonoidSquarePowerFiberCriterion | unverändert – Einzelstatement |
| 38 / 868 | MonoidSquarePowerFiber | unverändert – Einzelstatement |
| 38 / 966 | CommutativeMonoidIsCommutativeSemigroup | unverändert – Einzelstatement |
| 38 / 1001 | PowerMonoidUnitCharacterization | unverändert – Einzelstatement |
| 38 / 1057 | MonoidIdentityIsUnit | unverändert – Einzelstatement |
| 38 / 1103 | CommutativeMonoidDividesReflexive | unverändert – Einzelstatement |
| 38 / 1127 | CommutativeMonoidDividesTransitive | unverändert – Einzelstatement |
| 38 / 1204 | CommutativeMonoidUnitIffDividesIdentity | unverändert – Einzelstatement |
| 38 / 1352 | CommutativeCancellativeMonoidFactorDivisorUnit | unverändert – Einzelstatement |
| 38 / 1470 | CommutativeCancellativeMonoidPrimeIsIrreducible | unverändert – Einzelstatement |
| 38 / 1648 | SemigroupIsoMonoidImageActions | unverändert – Einzelstatement |
| 38 / 1679 | SemigroupIsoMonoidTransport | unverändert – Einzelstatement |
| 38 / 1717 | SemigroupIsoBetweenMonoidsIdentity | unverändert – Einzelstatement |
| 38 / 1738 | SemigroupIsoMonoidInversePair | unverändert – Einzelstatement |
| 38 / 1796 | SemigroupIsoBetweenMonoidsUnits | unverändert – Einzelstatement |
| 38 / 1854 | SemigroupIsoBetweenMonoidsIdentityAndUnits | unverändert – Einzelstatement |
| 38 / 1885 | MonoidHomComposition | unverändert – Einzelstatement |
| 38 / 2007 | NaturalAdditionMonoid | unverändert – Einzelstatement |
| 38 / 2026 | NaturalAdditiveCommutativeMonoid | unverändert – Einzelstatement |
| 38 / 2042 | NaturalMultiplicationMonoid | unverändert – Einzelstatement |
| 38 / 2061 | NaturalMultiplicativeCommutativeMonoid | unverändert – Einzelstatement |
| 39 / 251 | SemiringHomComposition | unverändert – Einzelstatement |
| 39 / 399 | NaturalSemiringMonoidStructures | unverändert – Einzelstatement |
| 39 / 422 | NaturalUnitalSemiring | unverändert – Einzelstatement |
| 39 / 464 | NaturalCommutativeUnitalSemiring | unverändert – Einzelstatement |
| 39 / 522 | SemiringSuccessorFunction | unverändert – Einzelstatement |
| 39 / 537 | SemiringZeroCarrier | unverändert – Einzelstatement |
| 39 / 575 | NaturalSemiringMapFunction | unverändert – Einzelstatement |
| 39 / 607 | NaturalSemiringMapZero | unverändert – Einzelstatement |
| 39 / 638 | NaturalSemiringMapAddOne | unverändert – Einzelstatement |
| 39 / 691 | NaturalSemiringMapOne | unverändert – Einzelstatement |
| 39 / 748 | NaturalSemiringMapAdditionZero | unverändert – Einzelstatement |
| 39 / 791 | NaturalSemiringMapAdditionStep | unverändert – Einzelstatement |
| 39 / 892 | NaturalSemiringMapAddition | unverändert – Einzelstatement |
| 39 / 922 | NaturalSemiringMapMultiplicationZero | unverändert – Einzelstatement |
| 39 / 962 | NaturalSemiringMapMultiplicationStep | unverändert – Einzelstatement |
| 39 / 1099 | NaturalSemiringMapMultiplication | unverändert – Einzelstatement |
| 39 / 1136 | NaturalSemiringCanonicalAdditiveMonoidHom | unverändert – Einzelstatement |
| 39 / 1183 | NaturalSemiringCanonicalMultiplicativeMonoidHom | unverändert – Einzelstatement |
| 39 / 1227 | NaturalSemiringCanonicalHomomorphism | unverändert – Einzelstatement |
| 39 / 1256 | NaturalSemiringHomPointwiseUnique | unverändert – Einzelstatement |
| 39 / 1355 | NaturalSemiringUniversalHomomorphism | unverändert – Einzelstatement |
| 39 / 1404 | NaturalSemiringMapSurjectiveIffFullImage | unverändert – Einzelstatement |
| 39 / 1437 | NaturalSemiringMapSurjectiveIffSuccessorInduction | unverändert – Einzelstatement |
| 39 / 1520 | NaturalSemiringMapInjectiveNoCollision | unverändert – Einzelstatement |
| 39 / 1574 | NaturalSemiringMapNoCollisionInjective | unverändert – Einzelstatement |
| 39 / 1613 | NaturalSemiringMapInjectiveIffNoCollision | unverändert – Einzelstatement |
| 39 / 1706 | NaturalSemiringMapInjectivePeanoCriterion | unverändert – Einzelstatement |
| 39 / 1753 | NaturalSemiringMapNotInjectiveIntoFiniteSemiring | unverändert – Einzelstatement |
| 39 / 1786 | NaturalSemiringMapIsoInjectiveSurjective | unverändert – Einzelstatement |
| 39 / 1832 | NaturalSemiringMapInjectiveSurjectiveIso | unverändert – Einzelstatement |
| 39 / 1882 | NaturalSemiringMapIsoIffInjectiveAndSurjective | unverändert – Einzelstatement |
| 39 / 1971 | NaturalOnePlusCommutative | unverändert – Einzelstatement |
| 39 / 1983 | NaturalAdditionNotGroupContradiction | unverändert – Einzelstatement |
| 39 / 2005 | NaturalAdditionNotGroup | unverändert – Einzelstatement |
| 39 / 2017 | NaturalRingInverseRequirementAtOne | unverändert – Einzelstatement |
| 39 / 2044 | NaturalNumbersNotRingConclusion | unverändert – Einzelstatement |
| 39 / 2067 | NaturalNumbersNotRing | unverändert – Einzelstatement |
| 40 / 119 | GroupBaseSemigroup | unverändert – Einzelstatement |
| 40 / 133 | GroupClosure | unverändert – Einzelstatement |
| 40 / 149 | GroupAssociativity | unverändert – Einzelstatement |
| 40 / 169 | GroupIdentityCarrier | unverändert – Einzelstatement |
| 40 / 183 | GroupLeftIdentity | unverändert – Einzelstatement |
| 40 / 198 | GroupRightIdentity | unverändert – Einzelstatement |
| 40 / 215 | GroupInverseUnique | unverändert – Einzelstatement |
| 40 / 330 | GroupInverseCarrier | unverändert – Einzelstatement |
| 40 / 343 | GroupInverseRight | unverändert – Einzelstatement |
| 40 / 356 | GroupInverseLeft | unverändert – Einzelstatement |
| 40 / 371 | GroupLeftCancellation | unverändert – Einzelstatement |
| 40 / 479 | GroupRightCancellation | unverändert – Einzelstatement |
| 40 / 587 | FiniteCancellativeSemigroupIsGroup | unverändert – Einzelstatement |
| 40 / 643 | GroupProductInverse | unverändert – Einzelstatement |
| 40 / 788 | AbelianGroupIsCommutativeMonoid | unverändert – Einzelstatement |
| 40 / 849 | GroupHomIdentityPreservation | unverändert – Einzelstatement |
| 40 / 889 | GroupHomInversePreservation | unverändert – Einzelstatement |
| 40 / 944 | GroupHomIsMonoidHom | unverändert – Einzelstatement |
| 40 / 985 | GroupHomComposition | unverändert – Einzelstatement |
| 40 / 1012 | GroupIdentityIsomorphism | unverändert – Einzelstatement |
| 40 / 1122 | LargePowerSemigroupUnitGroupReconstruction | unverändert – Einzelstatement |
| 40 / 1212 | GroupPowerSemigroupRigidity | unverändert – Einzelstatement |
| 40 / 1301 | GroupElementIsMonoidUnit | unverändert – Einzelstatement |
| 40 / 1315 | PowerGroupUnitsAreSingletons | unverändert – Einzelstatement |
| 40 / 1384 | PowerGroupsSingletonLayer | unverändert – Einzelstatement |
| 40 / 1446 | PowerGroupsSingletonTransport | unverändert – Einzelstatement |
| 40 / 1604 | GroupCompletionPairRelationChar | unverändert – Einzelstatement |
| 40 / 1625 | GroupCompletionPairRelationReflexive | unverändert – Einzelstatement |
| 40 / 1644 | GroupCompletionPairRelationSymmetric | unverändert – Einzelstatement |
| 40 / 1675 | GroupCompletionPairRelationTransitiveRearrangement | unverändert – Einzelstatement |
| 40 / 1711 | GroupCompletionPairRelationTransitive | unverändert – Einzelstatement |
| 40 / 1760 | GroupCompletionPairRepresentative | unverändert – Einzelstatement |
| 40 / 1781 | GroupCompletionPairEquivalence | unverändert – Einzelstatement |
| 40 / 1973 | GroupCompletionClassInCarrier | unverändert – Einzelstatement |
| 40 / 2020 | GroupCompletionClassEquality | unverändert – Einzelstatement |
| 40 / 2123 | GroupCompletionRepresentative | unverändert – Einzelstatement |
| 40 / 2219 | GroupCompletionOperationCompatible | unverändert – Einzelstatement |
| 40 / 2275 | GroupCompletionOperationQuotientDescent | unverändert – Einzelstatement |
| 40 / 2608 | GroupCompletionZeroCarrier | unverändert – Einzelstatement |
| 40 / 2636 | GroupCompletionOperationClosure | unverändert – Einzelstatement |
| 40 / 2714 | GroupCompletionOperationAssociative | unverändert – Einzelstatement |
| 40 / 2852 | GroupCompletionOperationCommutative | unverändert – Einzelstatement |
| 40 / 2920 | GroupCompletionOperationIdentity | unverändert – Einzelstatement |
| 40 / 3010 | GroupCompletionCommutativeMonoid | unverändert – Einzelstatement |
| 40 / 3119 | GroupCompletionEmbeddingFunction | unverändert – Einzelstatement |
| 40 / 3138 | GroupCompletionEmbeddingOperation | unverändert – Einzelstatement |
| 40 / 3212 | GroupCompletionEmbeddingIdentity | unverändert – Einzelstatement |
| 40 / 3244 | GroupCompletionEmbeddingMonoidHom | unverändert – Einzelstatement |
| 40 / 3313 | GroupCompletionEmbeddingInjective | unverändert – Einzelstatement |
| 40 / 3394 | GroupCompletionClassInverse | unverändert – Einzelstatement |
| 40 / 3500 | GroupCompletionInverseExistence | unverändert – Einzelstatement |
| 40 / 3556 | GroupCompletionAbelianGroup | unverändert – Einzelstatement |
| 40 / 3611 | GroupCompletionEmbeddingTheorem | unverändert – Einzelstatement |
| 40 / 3800 | RingAdditiveGroup | unverändert – Einzelstatement |
| 40 / 3814 | RingMultiplicativeSemigroup | unverändert – Einzelstatement |
| 40 / 3828 | RingMultiplicationClosure | unverändert – Einzelstatement |
| 40 / 3865 | RingNegativeCarrier | unverändert – Einzelstatement |
| 40 / 3878 | RingNegativeRight | unverändert – Einzelstatement |
| 40 / 3892 | RingNegativeLeft | unverändert – Einzelstatement |
| 40 / 3906 | RingDoubleNegative | unverändert – Einzelstatement |
| 40 / 3932 | RingLeftZeroAbsorption | unverändert – Einzelstatement |
| 40 / 3990 | RingRightZeroAbsorption | unverändert – Einzelstatement |
| 40 / 4050 | RingLeftNegativeProduct | unverändert – Einzelstatement |
| 40 / 4139 | RingRightNegativeProduct | unverändert – Einzelstatement |
| 40 / 4228 | RingNegativeTimesNegative | unverändert – Einzelstatement |
| 40 / 4264 | RingUnderlyingSemiring | unverändert – Einzelstatement |
| 40 / 4374 | RingHomZeroPreservation | unverändert – Einzelstatement |
| 40 / 4392 | RingHomNegativePreservation | unverändert – Einzelstatement |
| 40 / 4430 | RingHomComposition | unverändert – Einzelstatement |
| 40 / 4582 | IntegerAdditiveAbelianGroup | unverändert – Einzelstatement |
| 40 / 4657 | IntegerMultiplicativeCommutativeMonoid | unverändert – Einzelstatement |
| 40 / 4714 | IntegerCommutativeRing | unverändert – Einzelstatement |
| 40 / 4778 | RingCrossSumGivesDifferenceEquality | unverändert – Einzelstatement |
| 40 / 4865 | IntegerRingPairValueCarrier | unverändert – Einzelstatement |
| 40 / 4908 | IntegerRingMapRepresentativeIndependent | unverändert – Einzelstatement |
| 40 / 4970 | IntegerRingMapQuotientDescent | unverändert – Einzelstatement |
| 40 / 5483 | IntegerRingMapFunction | unverändert – Einzelstatement |
| 40 / 5501 | IntegerRingMapClassValue | unverändert – Einzelstatement |
| 40 / 5533 | IntegerRingMapAddition | unverändert – Einzelstatement |
| 40 / 5643 | IntegerRingMapMultiplication | unverändert – Einzelstatement |
| 40 / 5760 | IntegerRingMapConstants | unverändert – Einzelstatement |
| 40 / 5802 | IntegerRingCanonicalHomomorphism | unverändert – Einzelstatement |
| 40 / 5907 | IntegerRingUniversalHomomorphism | unverändert – Einzelstatement |
| 41 / 75 | FiniteGroupIsFiniteSemigroup | unverändert – Einzelstatement |
| 41 / 124 | PowerGroupSquareCoreReconstruction | unverändert – Einzelstatement |
| 41 / 318 | FiniteGroupSquareFiberBijections | unverändert – Einzelstatement |
| 41 / 427 | FiniteGroupSquarePowerSemigroupReconstruction | unverändert – Einzelstatement |
| 41 / 499 | FiniteGroupSquarePowerSemigroupReconstructionOneSidedNonempty | unverändert – Einzelstatement |
| 42 / 263 | SemilatticeIdentityPreservesOperation | unverändert – Einzelstatement |
| 42 / 293 | SemilatticeIdentityHomomorphism | unverändert – Einzelstatement |
| 42 / 314 | SemilatticeHomComposition | unverändert – Einzelstatement |
| 42 / 382 | SemilatticeIdentityIsomorphism | unverändert – Einzelstatement |
| 42 / 401 | SemilatticeIsoComposition | unverändert – Einzelstatement |
| 42 / 490 | JoinOrderFirstCarrier | unverändert – Einzelstatement |
| 42 / 504 | JoinOrderSecondCarrier | unverändert – Einzelstatement |
| 42 / 518 | JoinOrderEvaluation | unverändert – Einzelstatement |
| 42 / 538 | JoinOrderReflexive | unverändert – Einzelstatement |
| 42 / 555 | JoinOrderTransitive | unverändert – Einzelstatement |
| 42 / 599 | JoinOrderAntisymmetric | unverändert – Einzelstatement |
| 42 / 621 | JoinSemilatticeInducesOrder | unverändert – Einzelstatement |
| 42 / 655 | JoinPrincipalFilterChar | unverändert – Einzelstatement |
| 42 / 682 | JoinUpperLeft | unverändert – Einzelstatement |
| 42 / 714 | JoinUpperRight | unverändert – Einzelstatement |
| 42 / 732 | JoinLeastUpper | unverändert – Einzelstatement |
| 42 / 774 | JoinIsPairSupremum | unverändert – Einzelstatement |
| 42 / 909 | PairJoinUpperLeft | unverändert – Einzelstatement |
| 42 / 936 | PairJoinUpperRight | unverändert – Einzelstatement |
| 42 / 960 | PairJoinLeastUpper | unverändert – Einzelstatement |
| 42 / 996 | PairJoinIdempotent | unverändert – Einzelstatement |
| 42 / 1017 | PairJoinCommutative | unverändert – Einzelstatement |
| 42 / 1045 | PairJoinAssociative | unverändert – Einzelstatement |
| 42 / 1166 | PairJoinCharacterization | unverändert – Einzelstatement |
| 42 / 1195 | PairJoinRecoversOrder | unverändert – Einzelstatement |
| 42 / 1274 | MeetOrderEvaluation | unverändert – Einzelstatement |
| 42 / 1301 | MeetLowerLeft | unverändert – Einzelstatement |
| 42 / 1324 | MeetLowerRight | unverändert – Einzelstatement |
| 42 / 1347 | MeetIsPairInfimum | unverändert – Einzelstatement |
| 42 / 1437 | PowerSetUnionClosure | unverändert – Einzelstatement |
| 42 / 1455 | PowerSetUnionSemilattice | unverändert – Einzelstatement |
| 42 / 1477 | PowerSetIntersectionClosure | unverändert – Einzelstatement |
| 42 / 1493 | PowerSetIntersectionSemilattice | unverändert – Einzelstatement |
| 42 / 1517 | SubsetIffUnionEqualsRight | unverändert – Einzelstatement |
| 42 / 1550 | PowerSetUnionOrderIsInclusion | unverändert – Einzelstatement |
| 42 / 1569 | PowerSetIntersectionOrderIsInclusion | unverändert – Einzelstatement |
| 42 / 1815 | LatticeHomMeetSemilatticeHom | unverändert – Einzelstatement |
| 42 / 1848 | LatticeHomJoinSemilatticeHom | unverändert – Einzelstatement |
| 42 / 1881 | LatticeIdentityHomomorphism | unverändert – Einzelstatement |
| 42 / 1914 | LatticeHomComposition | unverändert – Einzelstatement |
| 42 / 1980 | LatticeIdentityIsomorphism | unverändert – Einzelstatement |
| 42 / 1999 | LatticeIsoComposition | unverändert – Einzelstatement |
| 42 / 2042 | LatticeOrdersCoincide | unverändert – Einzelstatement |
| 42 / 2105 | PowerSetMeetAbsorption | unverändert – Einzelstatement |
| 42 / 2118 | PowerSetJoinAbsorption | unverändert – Einzelstatement |
| 42 / 2136 | PowerSetLattice | unverändert – Einzelstatement |
| 42 / 2281 | ZeroJoinLeast | unverändert – Einzelstatement |
| 42 / 2576 | BoundedJoinTopGreatest | unverändert – Einzelstatement |
| 42 / 2601 | ZeroJoinGreatestAbsorbs | unverändert – Einzelstatement |
| 42 / 2657 | PairLowerBoundSetFinite | unverändert – Einzelstatement |
| 42 / 2671 | PairLowerBoundSetContainsZero | unverändert – Einzelstatement |
| 42 / 2697 | PairLowerBoundSetJoinClosed | unverändert – Einzelstatement |
| 42 / 2756 | JoinClosedMaximalIsGreatest | unverändert – Einzelstatement |
| 42 / 2796 | FiniteZeroJoinSemilatticeHasGreatest | unverändert – Einzelstatement |
| 42 / 2840 | FiniteZeroJoinSemilatticeIsBounded | unverändert – Einzelstatement |
| 42 / 2874 | FiniteZeroJoinSemilatticePairInfima | unverändert – Einzelstatement |
| 42 / 2999 | JoinSeparatorSetCharacterization | unverändert – Einzelstatement |
| 42 / 3017 | JoinSeparatorSetSubset | unverändert – Einzelstatement |
| 42 / 3038 | JoinSeparatorSetContainsLeft | unverändert – Einzelstatement |
| 42 / 3068 | JoinSeparatorSetFinite | unverändert – Einzelstatement |
| 42 / 3082 | StrictLowerSeparatorBelowRight | unverändert – Einzelstatement |
| 42 / 3133 | MinimalSeparatorJoinIrreducible | unverändert – Einzelstatement |
| 42 / 3271 | JoinIrreduciblesSeparate | unverändert – Einzelstatement |
| 42 / 3353 | NontrivialFiniteZeroJoinHasIrreducible | unverändert – Einzelstatement |
| 42 / 3415 | JoinIrreducibleProperLowerCarrier | unverändert – Einzelstatement |
| 42 / 3428 | JoinIrreducibleProperLowerFinite | unverändert – Einzelstatement |
| 42 / 3467 | JoinIrreducibleProperLowerJoinClosed | unverändert – Einzelstatement |
| 42 / 3575 | JoinIrreducibleLargestProperLower | unverändert – Einzelstatement |
| 43 / 61 | Enthaltende Teilfamilie ist Teilfamilie | unverändert – Einzelstatement |
| 43 / 75 | Vermeidende Teilfamilie ist Teilfamilie | unverändert – Einzelstatement |
| 43 / 89 | FamContainingAsAvoidingRelativeComplement | unverändert – Einzelstatement |
| 43 / 160 | Außenstehende Mengen sind nicht enthaltend | unverändert – Einzelstatement |
| 43 / 177 | Außenstehende Mengen sind nicht vermeidend | unverändert – Einzelstatement |
| 43 / 194 | Enthaltende Teilfamilie ist vereinigungsabgeschlossen | unverändert – Einzelstatement |
| 43 / 221 | UnionNotMemberFromBoth | unverändert – Einzelstatement |
| 43 / 240 | Vermeidende Teilfamilie ist vereinigungsabgeschlossen | unverändert – Einzelstatement |
| 43 / 270 | FiniteContainingSubfamily | unverändert – Einzelstatement |
| 43 / 283 | FiniteAvoidingSubfamily | unverändert – Einzelstatement |
| 43 / 353 | FranklFamNonempty | unverändert – Einzelstatement |
| 43 / 363 | FranklFamCarrierNonempty | unverändert – Einzelstatement |
| 43 / 373 | FranklFamFinite | unverändert – Einzelstatement |
| 43 / 383 | FranklFamUnionClosed | unverändert – Einzelstatement |
| 43 / 406 | Frankl-Vermutung bei enthaltener Einermenge | unverändert – Einzelstatement |
| 43 / 437 | Leere vermeidende Teilfamilie liefert Frankl | unverändert – Einzelstatement |
| 43 / 468 | Frankl-Vermutung bei nichtleerem Durchschnitt | unverändert – Einzelstatement |
| 43 / 540 | FranklPairAvoidADecomp | unverändert – Einzelstatement |
| 43 / 572 | FranklPairAvoidADisjoint | unverändert – Einzelstatement |
| 43 / 597 | FranklPairContainADecomp | unverändert – Einzelstatement |
| 43 / 639 | FranklPairContainADisjoint | unverändert – Einzelstatement |
| 43 / 682 | FranklPairMixed01Finite | unverändert – Einzelstatement |
| 43 / 698 | FranklPairMixedReverseInjection | unverändert – Einzelstatement |
| 43 / 796 | FranklPairAdjFunction | unverändert – Einzelstatement |
| 43 / 816 | FranklPairAdjEval | unverändert – Einzelstatement |
| 43 / 836 | FranklPairAdjInjection | unverändert – Einzelstatement |
| 43 / 917 | FranklPairPositiveBranch | unverändert – Einzelstatement |
| 43 / 990 | FranklPairNegativeBranch | unverändert – Einzelstatement |
| 43 / 1048 | FranklPairMemberFrankl | unverändert – Einzelstatement |
| 43 / 1100 | FranklFamPairMemberFrankl | unverändert – Einzelstatement |
| 43 / 1164 | OccQuotFamFranklFam | unverändert – Einzelstatement |
| 43 / 1206 | OccQuotCarrierFinite | unverändert – Einzelstatement |
| 43 / 1242 | OccQuotMembersFinite | unverändert – Einzelstatement |
| 43 / 1267 | OccQuotAvoidingMembership | unverändert – Einzelstatement |
| 43 / 1381 | OccQuotContainingMembership | unverändert – Einzelstatement |
| 43 / 1489 | OccQuotAvoidingPreimage | unverändert – Einzelstatement |
| 43 / 1530 | OccQuotAvoidingEqCard | unverändert – Einzelstatement |
| 43 / 1575 | OccQuotInjectionPullback | unverändert – Einzelstatement |
| 43 / 1651 | OccQuotRepresentativeHalfOcc | unverändert – Einzelstatement |
| 43 / 1680 | OccQuotHalfOccTransport | unverändert – Einzelstatement |
| 43 / 1711 | OccQuotFranklTransport | unverändert – Einzelstatement |
| 43 / 1742 | FranklFiniteMembersReduction | unverändert – Einzelstatement |
| 43 / 1896 | JoinIrreducibleTopFrankl | unverändert – Einzelstatement |
| 43 / 2000 | FranklJoinChains | unverändert – Einzelstatement |
| 43 / 2141 | CanonicalProfileFamilyMembership | unverändert – Einzelstatement |
| 43 / 2197 | CanonicalProfileFunction | unverändert – Einzelstatement |
| 43 / 2213 | CanonicalProfileEvaluation | unverändert – Einzelstatement |
| 43 / 2237 | CanonicalProfileSurjective | unverändert – Einzelstatement |
| 43 / 2284 | IrreducibleProfileSubset | unverändert – Einzelstatement |
| 43 / 2306 | IrreducibleProfileReflectsOrder | unverändert – Einzelstatement |
| 43 / 2350 | CanonicalProfileInjective | unverändert – Einzelstatement |
| 43 / 2410 | CanonicalProfileBijection | unverändert – Einzelstatement |
| 43 / 2436 | CanonicalProfileRepresentative | unverändert – Einzelstatement |
| 43 / 2474 | RelativeComplementIntersectionDeMorgan | unverändert – Einzelstatement |
| 43 / 2527 | RelativeComplementProfileUnionTransport | unverändert – Einzelstatement |
| 43 / 2561 | CanonicalProfilePairInfimumIntersection | unverändert – Einzelstatement |
| 43 / 2750 | CanonicalProfilePairInfimumUnion | unverändert – Einzelstatement |
| 43 / 2814 | CanonicalProfileFamilyUnionClosed | unverändert – Einzelstatement |
| 43 / 2919 | CanonicalZeroProfileEmpty | unverändert – Einzelstatement |
| 43 / 2953 | CanonicalProfileFamilyNonempty | unverändert – Einzelstatement |
| 43 / 2977 | CanonicalProfileCarrierNonempty | unverändert – Einzelstatement |
| 43 / 3029 | CanonicalUnionFamilyIsFranklFamily | unverändert – Einzelstatement |
| 43 / 3060 | CanonicalProfileMemberSubsetIrr | unverändert – Einzelstatement |
| 43 / 3089 | CanonicalCarrierElementIrreducible | unverändert – Einzelstatement |
| 43 / 3113 | CanonicalAvoidingMembership | unverändert – Einzelstatement |
| 43 / 3205 | CanonicalContainingMembership | unverändert – Einzelstatement |
| 43 / 3290 | CanonicalAvoidingPreimage | unverändert – Einzelstatement |
| 43 / 3337 | CanonicalContainingPreimage | unverändert – Einzelstatement |
| 43 / 3384 | BijectionAtMostHalfTransport | unverändert – Einzelstatement |
| 43 / 3438 | CanonicalHalfOccurrenceTransport | unverändert – Einzelstatement |
| 43 / 3628 | FranklSetImpliesSemilattice | unverändert – Einzelstatement |
| 43 / 3721 | BoundedExistentialAdjunction | unverändert – Einzelstatement |
| 43 / 3779 | BoundedUniversalSingleton | unverändert – Einzelstatement |
| 43 / 3801 | BoundedUniversalAdjunction | unverändert – Einzelstatement |
| 43 / 3851 | UnionFamilyAdjunction | unverändert – Einzelstatement |
| 43 / 3874 | IntersectionSingletonFamily | unverändert – Einzelstatement |
| 43 / 3892 | IntersectionFamilyAdjunction | unverändert – Einzelstatement |
| 43 / 3930 | FamilyIntersectionSubsetMember | unverändert – Einzelstatement |
| 43 / 3947 | FiniteIntersectionClosedFamilyIntersection | unverändert – Einzelstatement |
| 43 / 4023 | FiniteUnionClosedFamilyTotalUnion | unverändert – Einzelstatement |
| 43 / 4098 | RelativeComplementUnionDeMorgan | unverändert – Einzelstatement |
| 43 / 4117 | RelativeComplementEmpty | unverändert – Einzelstatement |
| 43 / 4141 | RelativeComplementSelf | unverändert – Einzelstatement |
| 43 / 4201 | FranklComplementMapFunction | unverändert – Einzelstatement |
| 43 / 4213 | FranklComplementMapInjective | unverändert – Einzelstatement |
| 43 / 4247 | FranklComplementMapSurjective | unverändert – Einzelstatement |
| 43 / 4275 | FranklComplementMapBijective | unverändert – Einzelstatement |
| 43 / 4295 | FranklAugmentedMemberSubsetCarrier | unverändert – Einzelstatement |
| 43 / 4317 | FranklComplementMemberSubsetCarrier | unverändert – Einzelstatement |
| 43 / 4335 | FranklAugmentedFamilyFinite | unverändert – Einzelstatement |
| 43 / 4350 | FamAvoidingMonotone | unverändert – Einzelstatement |
| 43 / 4373 | FranklAugmentedContainingUnchanged | unverändert – Einzelstatement |
| 43 / 4458 | FranklAugmentedFamilyUnionClosed | unverändert – Einzelstatement |
| 43 / 4534 | FranklComplementFamilyFinite | unverändert – Einzelstatement |
| 43 / 4550 | FranklComplementFamilyIntersectionClosed | unverändert – Einzelstatement |
| 43 / 4582 | FranklComplementOrderPartial | unverändert – Einzelstatement |
| 43 / 4611 | FranklComplementCommonUpperFiniteNonempty | unverändert – Einzelstatement |
| 43 / 4660 | FranklComplementPairSupremum | unverändert – Einzelstatement |
| 43 / 4878 | FranklComplementPairSupremumExistence | unverändert – Einzelstatement |
| 43 / 4970 | FranklComplementPairJoinOperation | unverändert – Einzelstatement |
| 43 / 5005 | FranklComplementSemilattice | unverändert – Einzelstatement |
| 43 / 5022 | FranklComplementOrderRecovered | unverändert – Einzelstatement |
| 43 / 5045 | FranklComplementFiniteLattice | unverändert – Einzelstatement |
| 43 / 5164 | FranklComplementNontrivial | unverändert – Einzelstatement |
| 43 / 5194 | FranklEmptyAdjunctionContainsEmpty | unverändert – Einzelstatement |
| 43 / 5207 | FranklEmptyAdjunctionCarrierUnchanged | unverändert – Einzelstatement |
| 43 / 5224 | FranklEmptyAdjunctionNonempty | unverändert – Einzelstatement |
| 43 / 5236 | FranklEmptyAdjunctionCarrierNonempty | unverändert – Einzelstatement |
| 43 / 5259 | FranklEmptyAdjunctionPreservesFamily | unverändert – Einzelstatement |
| 43 / 5282 | FranklEmptyAdjunctionHalfOccurrenceBack | unverändert – Einzelstatement |
| 43 / 5333 | FranklEmptyAdjunctionFranklBack | unverändert – Einzelstatement |
| 43 / 5351 | FranklEmptyFamilyGlobalEquivalence | unverändert – Einzelstatement |
| 43 / 5429 | JoinIrreduciblePrivatePointCharacterization | unverändert – Einzelstatement |
| 43 / 5536 | JoinIrreduciblePrivatePoint | unverändert – Einzelstatement |
| 43 / 5588 | FranklComplementAvoidingFibre | unverändert – Einzelstatement |
| 43 / 5637 | FranklComplementContainingFibre | unverändert – Einzelstatement |
| 43 / 5709 | FranklComplementPrivatePointTransport | unverändert – Einzelstatement |
| 43 / 5780 | FranklSemilatticeImpliesSet | unverändert – Einzelstatement |
| 43 / 6154 | FranklSetSemilatticeEquivalence | unverändert – Einzelstatement |
| 44 / 130 | MetricReverseTriangleInequality | unverändert – Einzelstatement |
| 44 / 173 | RealDistanceIsMetric | unverändert – Einzelstatement |
| 44 / 208 | DiscreteMetricIsMetric | unverändert – Einzelstatement |
| 44 / 236 | MetricSubspaceRestrictionIsMetric | unverändert – Einzelstatement |
| 44 / 272 | RealMetricBallIsEpsilonNeighborhood | unverändert – Einzelstatement |
| 44 / 287 | MetricBallShrinking | unverändert – Einzelstatement |
| 44 / 328 | MetricOpenBallsAreOpen | unverändert – Einzelstatement |
| 44 / 368 | RealAndMetricSequenceConvergenceAgree | unverändert – Einzelstatement |
| 44 / 385 | MetricSubspaceConvergenceAgree | unverändert – Einzelstatement |
| 44 / 406 | MetricSequenceLimitUnique | unverändert – Einzelstatement |
| 44 / 427 | ConstantMetricSequenceConverges | unverändert – Einzelstatement |
| 44 / 440 | MetricSubsequencePreservesLimit | unverändert – Einzelstatement |
| 44 / 459 | MetricFiniteModificationPreservesLimit | unverändert – Einzelstatement |
| 44 / 477 | MetricSequenceTailSameLimit | unverändert – Einzelstatement |
| 44 / 521 | ConvergentMetricSequenceBounded | unverändert – Einzelstatement |
| 44 / 537 | RealAndMetricSequenceBoundednessAgree | unverändert – Einzelstatement |
| 44 / 592 | RealAndMetricCauchySequenceAgree | unverändert – Einzelstatement |
| 44 / 609 | MetricSubspaceCauchyAgree | unverändert – Einzelstatement |
| 44 / 629 | MetricConvergentSequenceIsCauchy | unverändert – Einzelstatement |
| 44 / 646 | MetricCauchySequenceBounded | unverändert – Einzelstatement |
| 44 / 661 | MetricCauchyWithConvergentSubsequence | unverändert – Einzelstatement |
| 44 / 709 | RealMetricSpaceComplete | unverändert – Einzelstatement |
| 44 / 735 | DiscreteMetricSpaceComplete | unverändert – Einzelstatement |
| 44 / 751 | ReciprocalNaturalSequenceConvergesToZero | unverändert – Einzelstatement |
| 44 / 772 | PuncturedRealLineIncomplete | unverändert – Einzelstatement |
| 44 / 803 | MetricClosedSetContainsSequenceLimits | unverändert – Einzelstatement |
| 44 / 822 | ClosedSubspaceOfCompleteMetricSpace | unverändert – Einzelstatement |
| 44 / 878 | MetricIdentityConstantContinuous | unverändert – Einzelstatement |
| 44 / 900 | MetricDistanceFromPointContinuous | unverändert – Einzelstatement |
| 44 / 923 | MetricContinuousMapsPreserveLimits | unverändert – Einzelstatement |
| 44 / 950 | MetricSequentialContinuityCriterion | unverändert – Einzelstatement |
| 44 / 998 | MetricContinuousComposition | unverändert – Einzelstatement |
| 44 / 1053 | MetricIsometryPreservesStructure | unverändert – Einzelstatement |
| 44 / 1111 | InfiniteNaturalSubsetIncreasingEnumeration | unverändert – Einzelstatement |
| 44 / 1154 | FiniteMetricSetSequentiallyCompact | unverändert – Einzelstatement |
| 44 / 1185 | MetricSequentiallyCompactSetBounded | unverändert – Einzelstatement |
| 44 / 1217 | MetricSequentiallyCompactSetComplete | unverändert – Einzelstatement |
| 44 / 1237 | MetricSequentiallyCompactSetClosed | unverändert – Einzelstatement |
| 44 / 1270 | MetricContinuousImageSequentiallyCompact | unverändert – Einzelstatement |
| 44 / 1300 | DiscreteMetricConvergenceEventuallyConstant | unverändert – Einzelstatement |
| 44 / 1320 | BoundedDiscreteNaturalNumbersNotSequentiallyCompact | unverändert – Einzelstatement |
| 44 / 1347 | RealSequenceMonotoneSubsequence | unverändert – Einzelstatement |
| 44 / 1383 | RealSequenceBolzanoWeierstrass | unverändert – Einzelstatement |
| 44 / 1406 | RealClosedBoundedIntervalSequentiallyCompact | unverändert – Einzelstatement |
