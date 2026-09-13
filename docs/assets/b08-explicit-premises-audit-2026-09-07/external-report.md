# B08: Migration aller externen Verweise auf die präzisierten Umkehr- und Kompositionssätze

## Auflösung und Umfang

109 aktive Quellen wurden gelesen: alle anderen Banddateien einschließlich Band 00, `main.tex` und sämtliche aktiven TeX-Includes unter `tex/`, einschließlich der Übersicht. Archive, temporäre Fassungen und dauerhaft archivierte Auditkopien gehörten nicht zum Such- oder Änderungsbereich.

18.789 tatsächliche `FormulaRefAuto`-/`FormulaRefAutoFwd`-Aufrufe wurden vor der Migration erfasst. 334 Aufrufe in 20 Dateien lösen auf Band 08 auf, davon 81 auf dessen Umkehr- und Kompositionsabschnitt einschließlich der unveränderten Definitionen bzw. Sätze. Die Zuordnung erfolgte mit dem tatsächlichen Lua-Normalisierer aus `tex/impl/thmlookup.lua` und der eingefrorenen ursprünglichen B08-Registry. Es war kein bloßer Zeichenkettenvergleich nach ähnlichen Formeln. Eine ergänzende Auflösung gegen alle 44 Bandregister fand für die betroffenen Umkehr-/Kompositionsschlüssel keine alternativen Ziele in anderen Bänden. Die drei im Infrastrukturcode auftretenden bloßen Makrodeklarationen sind separat als Nichtaufrufe erfasst.

Die vollständigen Originalaufrufe einschließlich Argumentlisten, Beweisformeln und vorausgehender lokaler Belege stehen in `all-b08-external-references.json` und `inverse-composition-full-context.json`. `summary.json` enthält die Verteilung nach Dateien und ursprünglichen Registerzielen. `B08-registry-before.tsv` ist die vor den B08-Änderungen gesicherte Referenzgrundlage.

## Änderungen

68 ursprüngliche Aufrufe in zehn Dateien wurden auf die bestätigten stabilen IDs migriert. 60 betrafen die elf von Root geänderten Umkehrsätze, acht die von Agent01 geänderten Kompositionssätze. Weil zwei bisher gemeinsam behauptete Umkehrgleichungen jetzt durch jeweils zwei Theoremanwendungen und ∧I begründet werden, enthält die Endfassung 70 entsprechende ID-Aufrufe.

| Quelle | Migrierte ursprüngliche Aufrufe |
|---|---:|
| Band 09 | 2 |
| Band 10 | 6 |
| Band 11 | 2 |
| Band 20 | 6 |
| Band 21 | 3 |
| Band 28, Hauptdatei | 3 |
| Band 37 | 1 |
| Band 43 | 2 |
| B28-Isomorphiebeispiele | 40 |
| B08-Übersicht | 3 |

Alle 57 ursprünglichen tabellarischen Umkehr-Aufrufe hatten die erforderliche Bijektivität bereits als tatsächliche, vorhergehende Belegzeile verfügbar und ausdrücklich als erstes Argument angegeben. Geprüft wurde die Formel der referenzierten Zeile; eine Isomorphismusannahme wurde nicht als bloß impliziter Ersatz für die Bijektivität akzeptiert. Dies schließt die fortlaufend nummerierten Teile in B09/B28 ein. Bei den beiden Eindeutigkeitsaufrufen ist auch der zweite Beleg bereits der nötige Funktionstyp.

Acht dieser Umkehr-Aufrufe benötigten weitere Präzisierung der Elementprämissen in den B28-Beispielen: Sechs Anwendungen entnehmen das benötigte einzelne Element nun durch ∧E aus einer zuvor gebildeten Konjunktion `u,v∈B`. Zwei Zeilen mit zwei Umkehrgleichungen verwenden jetzt zwei getrennte Theoremanwendungen mit den jeweiligen ∧E-Prämissen und anschließend ∧I. Die Beweisformeln und alle Abhängigkeiten dieser Zeilen blieben unverändert.

Die sieben tabellarischen Aufrufe von `MutuallyInverseFunctionBijection` verwenden jetzt die von Agent01 bestätigte Reihenfolge:

1. `G:A→B`;
2. `F:B→A`;
3. `F∘G=Id_A`;
4. `G∘F=Id_B`.

Bei sechs Aufrufen mussten die vorhandenen Typenargumente getauscht werden. Der Aufruf für die frische Adjunktion übergab bisher lediglich die beiden gemeinsamen Typen-/Gleichungszeilen 15 und 22; er projiziert nun alle vier Einzelprämissen mit ∧E. Die bereits vorhandenen mathematischen Argumente innerhalb dieser Zeilen wurden durch die Migration nicht ersetzt oder als zusätzlich formalisiert bezeichnet.

Die B08-Übersicht verweist nun über IDs und zeigt die Bijektivität zusätzlich ausdrücklich in allen drei dort dargestellten Umkehraussagen. Sie verwendet passende Zeilenumbrüche für die längeren Prämissen. `InverseFunctionDef`, die unveränderten Sätze sowie Definitions- oder Theoremverweise mit anderen Registerzielen wurden nicht verändert.

## Validierung und Nachweise

Alle Beweisformeln, Zeilenzahlen und Abhängigkeiten der zehn betroffenen Quellen wurden vor und nach dem Eingriff parsergestützt exakt verglichen. Es gibt keine unbeabsichtigte Änderung dieser Felder. Die TeX-Klammern sind balanciert; die B28-Beispieldatei enthält weiterhin keine Theoremreferenz innerhalb einer anderen Theoremreferenz. Der globale Schrittindexscan meldet genau dieselben 35 bekannten Makrofortsetzungs-Blindstellen, ohne neue Stelle.

Der abschließende erneute Scan aller 109 aktiven externen Quellen umfasst nun 18.791 Aufrufe und findet **keinen** verbliebenen Aufruf, der gegen die Vorher-Registry auf eines der 26 geänderten alten Theoremziele auflöst. Das Ergebnis steht in `remaining-old-targets.json`.

Die begrenzten Originalkopien stehen unter `before/`, die vollständigen Diffs unter `diffs/`. `external-migration-ledger.json` dokumentiert für jeden der 68 ursprünglichen Aufrufe das Originalziel, die neue ID, Vorher-/Nachher-Aufruf und die konkret geprüften Prämissenformeln. `external-validation.json` enthält das abschließende Prüfergebnis und SHA-256-Werte der betroffenen Quellen.

Agent15 hat die 37 Inverse-ID-Anwendungen in den beiden B28-Quellen zusätzlich unabhängig geprüft (zwei im Hauptband, 35 in 33 Beispielzeilen). Sämtliche Bijektivitätsbelege, Elementprämissen und beide Eindeutigkeitsaufrufe sind bestätigt; keine weitere Korrektur war erforderlich. Der unabhängige Bericht steht unter `tmp/b08-explicit-premises/b28-inverse-application-review.md` und `.json`.

`target-map.json` stimmt mit den von Root und Agent01 bestätigten 11+15 IDs überein. Es wurden keine unterprämisierten Altformeln als Kompatibilitätsalias registriert. Die stabile-ID-Migration macht diese alten Schlüssel entbehrlich; die neuen vollständigen Strukturformeln können eigenständig registriert werden.

Für Root liegt zusätzlich `resolve-current-b08.py` vor. Es liest die **jeweils aktuelle** B08-Quelle und löst sämtliche dortigen Aufrufe gegen die eingefrorene Vorher-Registry auf. Standardmäßig erzeugt es nur das Inventar `b08-internal-current-inventory.json`. Die ausdrücklich aufzurufende Option `--apply-keys` ersetzt ausschließlich aufgelöste Schlüssel durch IDs, erhält sämtliche Beweisargumente und verweigert das Schreiben, falls sich die Quelle während der Auflösung geändert hat. Die B08-internen Prämissenargumente werden weiterhin von Root bearbeitet.

Es wurden keine B08-Hauptquelledits, keine Archiveingriffe und keine LaTeX-Builds durch diesen Agenten ausgeführt. Root koordiniert Builds und PDF-Prüfung; eine rein statische Migration ersetzt diese Abschlussprüfungen nicht.
