# Band 08: Abschluss der konkreten frühen Beweisbefunde

Sechs Beweise wurden bei unveränderten Hauptaussagen, IDs und Theoremnummern mit zusammen 70 nummerierten Schritten neu hergeleitet:

| Theorem/Teil | Korrektur |
|---|---|
| 8.2.1.8 | Surjektive Existenz und Injektivität ausdrücklich aus Bijektivität; zwei getrennte Zeugenannahmen und korrekte ∃!I-Entladung. |
| 8.2.2.1 (H2) | Funktionstyp und Surjektivität als tatsächliche Belegzeilen; Zeugenannahme durch ∃E, Elementannahme durch →I/∀I entlassen. |
| 8.3.1.4 | Beide Identitäts-/Symmetrieanwendungen mit den vorhandenen Schrittargumenten. |
| 8.3.1.7 | Getrennte Element- und Gleichheitsannahmen für Injektivität; eigener getypter Zeuge für Surjektivität; beide quantifizierten Kriterien ausdrücklich geschlossen. |
| 8.3.2.1 | Injektivität und Surjektivität der Einschränkung mit ihren tatsächlichen Annahmen; Bijektivität über den bereits getypt bewiesenen Inj+Sur-Satz. |
| 8.3.2.2 (H1), `BijectiveRestrictionSubsetMembershipImpliesTargetMembership` | Funktionstyp aus Bijektivität; `RestrictionDef` mit Teilmengen- und Funktionsprämisse, anschließend universale Instanziierung und vorwärts gerichtete =E. |

Zusätzlich wurden zwei konkret gefundene Gleichheitsrichtungen korrigiert, jeweils ohne Umnummerierung: `LayerPowerMapPreservesSubsetsBackward`, Schritt 22, und `FixedEmptyBijectionNonemptyPreimageForward`, Schritt 12. Letzterer verwendet die ausdrücklich zitierte Symmetrie von `X=∅`, bevor in `F(∅)=∅` vorwärts eingesetzt wird.

`early-proof-fixes.json` enthält die sechs vollständigen Vorher-/Nachher-Beweise sowie beide lokalen Richtungskorrekturen. `verify-early-proof-fixes.py` bestätigt die aktuellen Quellen gegen das Ledger und berechnet alle Abhängigkeiten der 70 neu geschriebenen Schritte einschließlich →I, ∃E und ∃!I. `early-proof-refcheck.lua` prüft die 13 verwendeten vorhandenen Referenzkeys mit dem tatsächlichen Lua-Normalisierer; alle sind auflösbar. `early-proof-validation.json` enthält den Quellenhash und die Einzelresultate.

Agent15 prüfte unabhängig alle acht betroffenen Teile mit zusammen 109 aktuellen Beweiszeilen und bestätigte Semantik, Gleichheitsrichtungen und Annahmenmengen ohne Befund; Belege: `final-fixes-independent-review.md` und `.json`. Die Quelle wurde danach für den von Root koordinierten Build freigegeben. Der Build deckte außerdem einen falschen `[thm]`-Selektor des Injektivitätsaxioms in 8.2.1.8 auf; Root änderte ihn in `[ax]`, ohne Formel oder Argumente zu verändern. Ledger und Quellenhash wurden danach aktualisiert. Der Referenzprüfer überprüft nun auch den Deklarationstyp aller 13 vorhandenen Keys; alle Keys und Selektoren passen. Die Originalbaselines bleiben unverändert. Dies ist eine begrenzte Beweisprüfung der konkreten Befunde, keine Behauptung vollständiger Formalisierung sämtlicher Beweise.
