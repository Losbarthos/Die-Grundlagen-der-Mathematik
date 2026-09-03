# Beweisprüfung von Band 27

Die Theoreme und ihre Teilbeweise wurden darauf geprüft, welche allgemeinen
Hilfsaussagen bereits vor der Wort- und Baumtheorie bereitstehen sollten.
Wortspezifische Konstruktionen bleiben in Band 27; wiederkehrende Eigenschaften
werden dort als eigene zitierbare Resultate formuliert.

Die PDF-Sichtprüfung hat außerdem eine mehrdeutige Notation aufgedeckt:
Konkatenationen werden jetzt geklammert gesetzt. Dadurch sind die beiden
Klammerungen im Assoziativitätsbeweis und die Auswertung eines gesamten
Konkatenationswortes sichtbar unterscheidbar. Die stabilen Resultat-IDs und
Formelschlüssel bleiben dabei erhalten.

## Die vier Ausgangspunkte

- `FiniteWordSetIntroduction` (jetzt Theorem 27.2.1.2) stellt die gewünschte Einführungsregel mit
  Potenzmengenzugehörigkeit und existierender endlicher Funktionstypisierung
  bereit. Der Schluss von `FiniteWordFromTyping` (jetzt 27.2.1.3) ist zusammengeführt.
- Die Eindeutigkeit des Indexes eines natürlichen Anfangsabschnitts steht als
  `PeanoNatSegInjective` (10.4.6.26) in Band 10. `FiniteWordLengthUnique`
  (jetzt 27.2.1.4) verwendet diesen
  Satz unmittelbar nach der Eindeutigkeit des Definitionsbereichs.
- `LetterWordFacts` (jetzt 27.2.2.7) enthält die Funktionstypisierung als Teilresultat (i).
  Danach folgen Länge eins, Nichtleerheit und Auswertung. `1≠0` steht als
  `PeanoOneNeZero` (10.4.4.12) in Band 10. Der allgemeine einelementige Funktionsgraph und
  seine Auswertung werden in Band 5 bewiesen.
- `FiniteWordLengthZeroIffEmpty` (27.2.2.3) und
  `FiniteWordLengthNonzeroIffNonempty` (27.2.2.4) behandeln das Leerwort und die
  Null-/Nichtnull-Länge mit einzeln registrierten Richtungen. Das
  Nichtleerwortkriterium zitiert diese Resultate.

## Allgemeine Grundlagen in früheren Bänden

| Band | Resultate und Verwendungszweck |
| --- | --- |
| 3 – Mengenlehre | `TermImageSetUniqueExists`: gemeinsame Grundlage der Bildmengenkonstruktionen; `ThreeElementsInPair`: wiederverwendbares Zweiermengenkriterium im Binärbaumbeweis. |
| 5 – Funktionen | `SingletonGraphFunction`, `SingletonGraphValue`: Grundlage der Buchstabenwörter; `IndexedSubsetFamilyCoverUnion`: Vereinigung einer überdeckenden Familie von Teilmengen. |
| 7 – Surjektive Funktionen | `ProductComprehensionMembership`: Elementkriterium für mit Projektionen ausgesonderte Paarmengen. |
| 10 – Natürliche Zahlen | Eindeutige Anfangsabschnitte, Natürlichkeit ihrer Elemente, Eins-Anfangsabschnitt, Nichtnullsummen, eindeutiger Vorgänger sowie Zwei- und Dreiblockzerlegung und verschobene Indizes. |
| 21 – Folgen | Existenz, Definition und Funktionalität verschobener Folgengraphen; additive und geordnete Verschachtelung wachsender Mengenfolgen. |

Bereits verwendete IDs der verschobenen Bildmengen, der Blockzerlegung und der
verschobenen Graphen bleiben beim Umzug erhalten. Ihre Verweise führen nach
dem Neubau in den jeweiligen Grundlagenband.

## Indizierung und Ausgaben

Die Baumquelle trägt nun durchgehend Bandnummer 26. Einzelbände und Gesamtband
verwenden getrennte Registries und dieselbe lokale Resultatnummerierung.
Der Gesamtlauf prüft die Resultatregistrierungen gegen die AUX-Dateien und
gleicht die Indizes des Gesamtbands mit denen der Einzelbände ab.

Der neue Index von Band 27 enthält 71 Haupttheoreme, 132 einzeln zitierbare
Teilresultate und 27 Definitionen. Die 43 Einzelbände enthalten zusammen
4.089 unterschiedliche Resultatanker, darunter 789 Teilresultate.

Die veröffentlichten PDF-Dateien enthalten Verweise auf die tatsächlich
vorhandenen benannten Nachbar-PDFs. Die Publikationsprüfung kontrolliert auch
die benannten Sprungziele. Der reproduzierbare Ablauf steht in
[BUILDING.md](../BUILDING.md).

## Einzelprüfung

Die folgenden Listen dokumentieren die Prüfung sämtlicher Theoreme und
Teilresultate von Band 27; die Zuordnung erfolgt über stabile IDs, da sich
gedruckte Nummern durch die Ergänzungen ändern.

### Wortmenge und Konkatenation: 26 Haupttheoreme

| Theorem-ID | Befund |
| --- | --- |
| `FiniteWordSetMembership` | Inhaltlich lokal: unmittelbares Elementkriterium der Wortmengendefinition. |
| `FiniteWordSetIntroduction` | Eigenständige Einführungsrichtung ergänzt; die vom Nutzer gewünschte Prämissenform ist unmittelbar zitierbar. |
| `FiniteWordFromTyping` | Inhaltlich lokal; Produktmonotonie und Potenzmengenkriterium werden zitiert. Schluss durch `FiniteWordSetIntroduction` zusammengeführt. |
| `FiniteWordLengthUnique` | Anfangsabschnittseindeutigkeit nach B10 als `PeanoNatSegInjective` ausgelagert; lokale Argumentation beschränkt sich auf die Domäne des Wortgraphen. |
| `FiniteWordTyping` | Inhaltlich lokal: eindeutige Existenz, Längendefinition und Iota-Auswertung. |
| `FiniteWordLengthFromTyping` | Inhaltlich lokal: Eindeutigkeit der bereits definierten Länge. Voraussetzungen und Zeilenverweise geprüft. |
| `EmptyWordTyping` | Eigenständig herausgestellt; folgt aus der leeren Funktion und `PeanoNatSegZero`. |
| `EmptyWordLength` | Benutzt die ausgelagerte Leerworttypisierung und die allgemeine Längenbestimmung. |
| `FiniteWordLengthZeroIffEmpty` | Eigenständige Kennzeichnung ergänzt; verhindert wiederholte Herleitung im Nichtleerwortkriterium. |
| `FiniteWordLengthNonzeroIffNonempty` | Beide Nichtnullrichtungen eigenständig ergänzt; folgt aus der Nullkennzeichnung. |
| `NonemptyWordMembership` | Lokales Mengen-Differenzkriterium; Nichtnullkennzeichnung wird zitiert. Verwendet das vorhandene negative Singleton-Kriterium. |
| `NonemptyWordTyping` | Inhaltlich lokal; Folgerungen aus dem Nichtleerwortkriterium und der allgemeinen Worttypisierung. |
| `LetterWordFacts` | Typisierung eigenständig als (i); Einpunktgraph und Auswertung nach B05, `NatSeg 1={0}` sowie `1≠0` nach B10 ausgelagert. Reihenfolge Typisierung, Länge, Nichtleere, Auswertung beseitigt doppelte Längenherleitung. |
| `WordConcatenationMembership` | Inhaltlich lokal: Definition der Konkatenation, Vereinigung und verschobener Graph. Existenz/Definition des allgemeinen verschobenen Graphen stehen in B21. |
| `WordConcatenationIndexBlocksDisjoint` | Arithmetischer Kern nach B10 ausgelagert: `PeanoNatSegElementNatural` und `PeanoTailAvoidsInitialSegmentLeft`. |
| `WordConcatenationInitialGraphSubset` | Inhaltlich lokale Graphtypisierung; verwendet vorhandene Anfangsabschnittsinklusion und Produktmonotonie. Keine neue arithmetische Herleitung. |
| `WordConcatenationShiftedGraphSubset` | Indexargument durch `PeanoNatSegShiftMembership` aus B10 verkürzt; verbleibend lokale Graph-/Werttypisierung. |
| `WordConcatenationGraphTotal` | Zweiblockzerlegung wird mit `PeanoNatSegAddMembership` aus B10 zitiert; die Wahl des passenden Wortwertes bleibt lokal. |
| `WordConcatenationGraphFunctional` | Verschobene Graphfunktionalität nach B21 ausgelagert. Anfangsblock im Review korrigiert: explizite Typisierung von `u`, Auswertung beider Paare und vollständige Prämissenabhängigkeit. Gemischte Blöcke benutzen deren bereits bewiesene Disjunktheit. |
| `WordConcatenationTyping` | Inhaltlich lokal: vereinigter Graph, Totalität und Funktionalität; allgemeines Graphkriterium aus B05 wird zitiert. Koordinaten folgen aus enthaltenen Paaren. |
| `WordConcatenationClosure` | Eigenständige Abgeschlossenheit ergänzt; vermeidet wiederholte Endlichkeitsschlüsse in der Assoziativität. |
| `WordConcatenationLength` | Inhaltlich lokale Längenbestimmung durch Konkatenationstypisierung. |
| `WordConcatenationFixedCutCancellation` | Wortbezogener Kern bleibt lokal. Allgemeine Additionskürzung und Funktionsextensionalität werden zitiert. |
| `WordConcatenationIdentity` | Wortbezogene Leerwortgesetze bleiben lokal. Im Review fehlende Natürlichkeitsvoraussetzungen von Wortlänge und Index ergänzt; Nulladdition wird jetzt mit ihren korrekten Voraussetzungen zitiert. |
| `WordConcatenationAssociative` | Arithmetische Dreifachzerlegung nach B10 als `PeanoNatSegThreeBlockMembership` ausgelagert. Klammerungstypisierungen benutzen `WordConcatenationClosure`. Zwei Indexblöcke und die Natürlichkeit von `h` durch B10-Verweise ersetzt; punktweiser Beweis von 62 auf 58 Schritte verkürzt und vollständig neu nummeriert. Der zuvor gefundene Fehlverweis entfällt damit. Koordinatenvergleich bleibt inhaltlich lokal. |
| `NonemptyWordConcatenationClosure` | Nichtnullsumme nach B10 als `PeanoAddNonzeroLeft` ausgelagert; verbleibend Konkatenationslänge und Nichtleerwortkriterium. |

### Teilresultate der frühen Worttheorie

| Teilresultat-ID | Befund |
| --- | --- |
| `FiniteWordLengthNatural` | Lokal; Iota-Auswertung. |
| `FiniteWordTypingAtLength` | Lokal; Iota-Auswertung. |
| `EmptyWordFinite` | Lokal; zitiert `EmptyWordTyping`. |
| `EmptyWordLengthZero` | Lokal; zitiert Leerwortendlichkeit und -typisierung. |
| `FiniteWordLengthZeroImpliesEmpty` | Neu selbstständig herausgestellt; leere Funktion aus B05 wird zitiert. |
| `FiniteWordEmptyImpliesLengthZero` | Neu selbstständig herausgestellt; Einsetzen des Leerwortes. |
| `FiniteWordNonemptyImpliesLengthNonzero` | Neu selbstständig herausgestellt; Kontraposition der Nullkennzeichnung. |
| `FiniteWordLengthNonzeroImpliesNonempty` | Neu selbstständig herausgestellt; umgekehrte Nichtnullrichtung. |
| `NonemptyWordMembershipElimination` | Lokal; negatives Singleton-Kriterium und Nichtnulllemma. |
| `NonemptyWordMembershipIntroduction` | Lokal; umgekehrte Richtung mit den gleichen ausgelagerten Grundlagen. |
| `NonemptyWordFinite` | Lokal; direkte Folgerung aus dem Elementkriterium. |
| `NonemptyWordLengthNatural` | Lokal; allgemeine Längentypisierung wird zitiert. |
| `NonemptyWordTypingAtLength` | Lokal; allgemeine Worttypisierung wird zitiert. |
| `LetterWordTyping` | Neu selbstständig; allgemeiner Einpunktgraph B05 und Eins-Anfangsabschnitt B10. |
| `LetterWordLengthOne` | Lokal; Typisierung bei eins liefert die Länge. |
| `LetterWordNonempty` | Lokal; benutzt Länge eins und `PeanoOneNeZero`. |
| `LetterWordValueZero` | Allgemeine Auswertung eines Einpunktgraphen nach B05 ausgelagert. |
| `WordConcatenationInitialBlockFunctional` | Korrigiert: Funktionstypisierung explizit; `u(q)=a` und `u(q)=b` liefern die Gleichheit. |
| `WordConcatenationMixedBlocksImpossible` | Lokal; wertunabhängiger Indexwiderspruch durch vorhandenes Disjunktheitsresultat. |
| `WordConcatenationShiftedBlockFunctional` | Kern nach B21 als `ShiftedWordGraphFunctional` ausgelagert. |
| `WordConcatenationTypingPart` | Lokal; allgemeines eindeutiges Graphkriterium B05 wird benutzt. |
| `WordConcatenationInitialCoordinate` | Lokal; Paar im Anfangsgraphen und Funktionsauswertung. |
| `WordConcatenationShiftedCoordinate` | Lokal; Paar im verschobenen Graphen und Funktionsauswertung. |
| `WordConcatenationFixedCutLeft` | Lokal; Anfangskoordinaten und Extensionalität. |
| `WordConcatenationFixedCutRight` | Lokal; vorhandene Additionskürzung, verschobene Koordinaten und Extensionalität. |
| `WordConcatenationLeftIdentity` | Korrigiert: `|w|∈N` und `i∈N` vor Nulladditionen explizit; neu nummeriert. |
| `WordConcatenationRightIdentity` | Korrigiert: `|w|∈N` vor Nulladdition explizit; neu nummeriert. |
| `WordConcatenationAssociativityLeftTyping` | Lokal; vorhandene Konkatenationsabgeschlossenheit und -länge. |
| `WordConcatenationAssociativityRightTyping` | Lokal; zusätzlich vorhandene Additionsassoziativität. |
| `WordConcatenationThreeBlockDecomposition` | Arithmetischer Beweis nach B10 ausgelagert; nur Spezialisierung auf Wortlängen. |

### Verschobene bestehende Resultate

| ID | Neuer Ort |
| --- | --- |
| `TranslatedImageSetUniqueExists` | B10; unmittelbare Instanz von `TermImageSetUniqueExists` aus B03. |
| `TranslatedImageSetDef` | B10; allgemeine verschobene Bildmenge. |
| `WordIndexBlockDecomposition` | B10; arithmetische Blockzerlegung, bestehende ID für externe Verweise erhalten. |
| `ShiftedWordGraphUniqueExists` | B21; allgemeiner verschobener Folgengraph. |
| `ShiftedWordGraphDef` | B21; zugehörige allgemeine Definition. |
| `ShiftedWordGraphFunctional` | B21; allgemeine Funktionalität des verschobenen Folgengraphen. |


### Endzerlegung bis Baumauswertung: 45 Haupttheoreme

| Theorem-ID | Befund | Registrierte Teilresultate |
| --- | --- | --- |
| `LetterWordInjectivity` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `FiniteWordLengthOneCharacterization` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `WordAppendLetterLength` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `WordAppendLetterLastCoordinate` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `NonemptyWordRightDecomposition` | Endwert-Anhängen und Buchstaben-Injektivität separat; Vorgängertypisierung benötigt Nichtnullprämisse. | `NonemptyWordRightDecompositionExistence`, `NonemptyWordRightDecompositionJointUniqueness` |
| `NonemptyWordInduction` | Länge-eins-Charakterisierung und Anhängelänge als frühere Wortsätze eingesetzt. | — |
| `NonemptyWordRecursion` | Paar-Aussonderung B07; eindeutiger Vorgänger B10; Familienvereinigung B05; wiederholte Anhängelängen ersetzt. | `NonemptyWordRecursionBaseGraphCarrier`, `NonemptyWordRecursionBaseGraphCriterion`, `NonemptyWordRecursionTransitionCriterion`, `NonemptyWordRecursionOperatorTyping`, `NonemptyWordRecursionOperatorEquation`, `NonemptyWordRecursionSequenceTyping`, `NonemptyWordRecursionSequenceBase`, `NonemptyWordRecursionSequenceStep`, `NonemptyWordRecursionLayerCriterion`, `NonemptyWordRecursionDomainFamilyTyping`, `NonemptyWordRecursionDomainFamilyEquation`, `NonemptyWordRecursionStageDecomposition`, `NonemptyWordRecursionStageBase`, `NonemptyWordRecursionStageStep`, `NonemptyWordRecursionStages`, `NonemptyWordRecursionStageUniqueCover`, `NonemptyWordRecursionStageUnion`, `NonemptyWordRecursionExistence`, `NonemptyWordRecursionUniqueness` |
| `LeftWordFoldExistence` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `LeftWordFoldCharacterization` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | `LeftWordFoldCharacterizationTyping`, `LeftWordFoldCharacterizationLetter`, `LeftWordFoldCharacterizationStep` |
| `LeftWordFoldFunction` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `LeftWordFoldEquations` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | `LeftWordFoldLetter`, `LeftWordFoldStep` |
| `TreeNodeCodeTyping` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | `TreeNodeCodeLeftFinite`, `TreeNodeCodeRightFinite`, `TreeNodeCodeLeftLengthNatural`, `TreeNodeCodeRightLengthNatural`, `TreeNodeCodeTagTyping`, `TreeNodeCodeTagNonempty`, `TreeNodeCodePayloadNonempty`, `TreeNodeCodeTagFinite`, `TreeNodeCodePayloadFinite` |
| `TreeConstructorNoConfusion` | Buchstaben-Injektivität ersetzt Auswertung bei null in Blatt- und Knotencodebeweisen. | `TreeLeafConstructorInjective`, `TreeConstructorsDisjoint`, `TreeNodeConstructorLeftInjective`, `TreeNodeConstructorRightInjective` |
| `TreeGenerationStepFunction` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `TreeGenerationStepMonotonicity` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `TreeStageSequenceTyping` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `TreeStageZeroEquation` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `TreeStageSuccessorEquation` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `TreeStageTyping` | Gesamte Stufenfolge einmal separat typisiert. | `TreeStagePowerSetTyping`, `TreeStageCarrierSubset` |
| `TreeStageMonotone` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | `TreeStageMonotoneBase`, `TreeStageMonotoneStep` |
| `TreeStageAdditiveNested` | Induktionsargument in allgemeinen Mengenfolgensatz B21 ausgelagert. | — |
| `TreeStageNested` | Allgemeiner Mengenfolgensatz B21 eingesetzt. | — |
| `TreeStageSubsetTreeSet` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `TreeCommonStage` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `TreeConstructorClosure` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | `TreeLeafClosure`, `TreeNodeClosure` |
| `TreeConstructorDecomposition` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | `TreeConstructorDecompositionForward`, `TreeConstructorDecompositionBackward` |
| `FullPlanarBinaryTreeStructuralInduction` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | `TreeStructuralInductionBase`, `TreeStructuralInductionStep` |
| `TreeRecursionOperatorTransform` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | `TreeRecursionOperatorDomainPowerSet`, `TreeRecursionOperatorGraphPowerSet`, `TreeRecursionOperatorCarrier`, `TreeRecursionOperatorLeafFiber`, `TreeRecursionOperatorNodeFiber`, `TreeRecursionOperatorFunction`, `TreeRecursionOperatorLeafEquation`, `TreeRecursionOperatorNodeEquation` |
| `FullPlanarBinaryTreeRecursion` | Vereinigung der überdeckenden Stufenträger durch allgemeinen B05-Satz ersetzt. | `TreeRecursionStageOperatorFunction`, `TreeRecursionStageEmptyGraph`, `TreeRecursionStageFunction`, `TreeRecursionStageZeroEquation`, `TreeRecursionStageSuccessorEquation`, `TreeRecursionStageTypingBase`, `TreeRecursionStageTypingStep`, `TreeRecursionStageTyping`, `TreeRecursionCoherenceBase`, `TreeRecursionCoherenceStep`, `TreeRecursionSuccessorCoherence`, `TreeRecursionIteratedCoherenceBase`, `TreeRecursionIteratedCoherenceStep`, `TreeRecursionIteratedCoherence`, `TreeRecursionRemoteCoherence`, `TreeRecursionDomainFunction`, `TreeRecursionDomainEquation`, `TreeRecursionDomainUnion`, `TreeRecursionPairwiseCoherence`, `TreeRecursionUnionTyping`, `TreeRecursionUnionStageEquation`, `TreeRecursionUnionLeafEquation`, `TreeRecursionUnionNodeEquation`, `TreeRecursionUniqueness` |
| `BinaryAddressPrefixSeparation` | Buchstaben-Injektivität unmittelbar eingesetzt. | `BinaryAddressPrefixJointInjective`, `BinaryAddressPrefixImagesDisjoint` |
| `BinaryAddressChildrenDistinct` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `BinaryAddressGraftBinaryOperation` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `GoodBinaryAddressSetConstructors` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | `GoodBinaryAddressSetLeaf`, `GoodBinaryAddressSetGraft` |
| `TreePositionMapExistenceUnique` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `TreePositionSetEquations` | Alle drei Teilresultate mit eigenen stabilen Schlüsseln registriert. | `TreePositionSetTyping`, `TreePositionSetLeafEquation`, `TreePositionSetNodeEquation` |
| `TreePositionSetIsGood` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | `TreePositionSetGoodLeaf`, `TreePositionSetGoodNode` |
| `GoodBinaryAddressSetIsFiniteOrderedFullBinaryTree` | Drei Elemente einer Zweiermenge nach B03; Verschiedenheit der Adresskinder eigenes frühes Adresslemma. | `GoodBinaryAddressGraphSimple`, `GoodBinaryAddressRootPathsUnique`, `GoodBinaryAddressChildren`, `GoodBinaryAddressGraphFullBinary` |
| `BracketCodePositionGraphIsFiniteOrderedFullBinaryTree` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `NonemptyWordConcatenationBinaryOperation` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `TreeLeafWordExistenceUnique` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `TreeLeafWordEquations` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | `TreeLeafWordTyping`, `TreeLeafWordLeafEquation`, `TreeLeafWordNodeEquation` |
| `WordBracketingMembership` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `WordBracketingExistence` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `TreeEvaluationExistenceUnique` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | — |
| `TreeEvaluationEquations` | Grundlagen werden zitiert; der wort- oder baumspezifische Beweis bleibt hier. | `TreeEvaluationTyping`, `TreeEvaluationLeafEquation`, `TreeEvaluationNodeEquation` |

## Abschließende Validierung am 3. September 2026

Alle 45 PDF-Ausgaben wurden neu gebaut und unter `output/pdf/` aktualisiert:
43 Einzelbände, die reMarkable-Ausgabe und der Gesamtband. Zusammen enthalten
sie 4.044 Seiten; der Gesamtband umfasst 1.975 Seiten.

- Die vollständigen Resultat-IDs und tatsächlichen AUX-Nummern stimmen in
  allen 43 Bänden zwischen Einzel- und Gesamtausgabe überein.
- Der abschließende Audit der ausgegebenen PDFs bestätigt 47.755 gültige
  interne und 26.904 gültige bandübergreifende Sprungziele.
- Neue und überarbeitete Beweisstellen wurden gezielt gerendert und visuell
  geprüft. Satzköpfe, Teilresultatnummern und lange Begründungen sind lesbar.
- Der Gesamtband enthält eine gemeinsame Titelseite und ein gemeinsames
  Inhaltsverzeichnis. Der Autorenname erscheint im sichtbaren Text genau einmal.
- Der Ausgabeordner enthält genau die 45 erwarteten PDFs und keine temporären
  Ersatz- oder Sicherungsdateien.
