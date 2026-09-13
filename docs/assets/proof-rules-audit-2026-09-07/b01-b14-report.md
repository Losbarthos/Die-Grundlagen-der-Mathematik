# Regelprüfung Band 01–14

Ausgangsstand: bestehende, umfangreiche uncommitted Änderungen unverändert übernommen; byteweise Ausgangskopien in `b01-b14-baseline/`, isolierter Änderungsdiff in `b01-b14-changes.patch`.

## Prüfung

- Alle 14 aktiven Bandquellen mit dem geklammerten Parser `scripts/proof-source-audit.py` geprüft: ursprünglich 14.912 Tabellenzeilen.
- Zweite, breitere Prüfung entfernt zunächst echte `FormulaRefAuto`-Aufrufe und Regelmakros und sucht anschließend sämtliche verbliebenen Wörter in Begründungen. Dadurch wurden auch „Spezialisierung“, „voriger Teil“, Abkürzungen und bloße Referenzsammlungen erfasst.
- Band 01 enthält die verwendeten elementaren Regeln; diese und `tex/impl/commands/rules.tex` wurden gelesen. Keine Regelmakros oder gemeinsamen Dateien geändert.

## Änderungen

- **Band 08 / TranspositionBijectionExists**: 11 Metaprosa-Begründungen beseitigt. Fallterm ausdrücklich als verschachtelter bereits eingeführter `IfThenElse`-Term bestimmt. Konstruktion mit zwei ausgeschriebenen `∨E`-Fallzweigen und korrekten Entladungen; Konstruktionsteil als `TranspositionTermExists` verlinkt. Werte in `TranspositionTermValues` nachgewiesen. `TranspositionTermBijective` verwendet bewiesene Werte, echte Fallannahmen, Gleichheitselimination, Involution, einzeln eingeführte beschränkte Variablen, `→I`, `∀I`, `∃I`, `∃E`. Injektivität und Surjektivität erhalten vollständig quantifizierte Kriterien.
- **Band 09 / RetractionFiberBijection**: sämtliche 18 Metaprosa-/Referenzsammlungsbegründungen in der Faserverklebung ersetzt. Funktionswerte, Faserzugehörigkeit, Typübergänge und Gleichheiten sind eigene formale Zeilen. Hilfsterm `k_y` steht als reine Abkürzung außerhalb der Beweistabelle. Injektivität und Surjektivität besitzen explizite Quantifizierung und Zeugenentladung. Die Totalität der Auswahlrelation besitzt ein referenzierbares Teiltheorem `RetractionFiberSelectionTotal`; der Schluss verwendet diese Referenz statt „voriger Teil“. Die Definition von `C(U)` wird durch `∀E`, `→E`, `∧E`, `→I`, `∀I` behandelt.
- Funktions-Extensionalitätsreferenzen in Band 05/06/08/09/10 sind Verweise auf einen eingeführten Satz, keine Metaprosa; unverändert.

## Bewusst beibehalten

Band 10, Induktionsregel als schematisches Theorem, ursprüngliche Zeile 916: `[x∈N,P(x)] ⋮ P(Succ(x))` ist die ausdrücklich im Theorem vorausgesetzte Unterableitung. Sie wird im Beweis eingesetzt und anschließend korrekt durch `→I` und `∀I` geschlossen. Sie ist keine unbegründete metasprachliche Abkürzung eines zu beweisenden Arguments.

## Validierung

Die geänderten Quellen sind mit dem balancierten Beweisparser vollständig lesbar. Keine Builds/PDF-Änderungen durch diesen Agenten. Layout- und Gesamtbuildprüfung übernimmt Root.

Aktueller Tabellenumfang: 15021 Zeilen. Verbliebene Wortkandidaten: 1.

- `Bd. 10 - Natürliche Zahlen.tex:916`: `\begin{aligned}[t]&[x\in\mathbb{N},P(x)]\\&\vdots P(\Succ(x))(3,4)\end{aligned}`
