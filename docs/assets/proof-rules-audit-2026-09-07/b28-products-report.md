# Formalisierte Produktbeweise in B28

Die vorbereiteten Produktblöcke wurden abschließend mathematisch geprüft, erweitert und in der jeweils aktuellen `tex/B28-isomorphism-examples.tex` angewendet. Vorhandene Theoremdeklarationen einschließlich aller KR-Anzeigen, Original-Strukturformeln und IDs wurden dabei vollständig unverändert erhalten. Andere parallel bearbeitete Teile wurden nicht überschrieben.

| Beweisteil | neue Zeilen |
| --- | ---: |
| SemigroupDirectProductIsSemigroup | 44 |
| SemigroupCoordinateProductForwardFacts (neu registrierter Hilfsteil) | 32 |
| SemigroupCoordinateProductInverseFacts (neu registrierter Hilfsteil) | 32 |
| SemigroupDirectProductCarrierBijection | 66 |
| Operationserhaltung des direkten Isomorphismenprodukts | 43 |
| SemigroupBinaryProductIsSemigroup | 79 |

Die wichtigste Änderung gegenüber dem ersten Entwurf betrifft die Funktionskonstruktion: `TypedFunctionDefinitionPrinciple` folgert die eindeutige Existenz einer Funktion und erlaubt allein noch keine Typbehauptung für einen bereits benannten Term. Die endgültige Fassung verwendet deshalb explizite Graph-Mengenterme für die beiden inneren Koordinatenfunktionen und die äußeren Abbildungen F und H. Die bewiesenen Teilsätze `TypedTermGraphFunction` und `TypedTermGraphValues` liefern jeweils den Typ und die Grundgleichung des genau ausgeschriebenen Graphen. Die Koordinaten gehören nach Abgeschlossenheit beziehungsweise Werttypisierung in die jeweilige Komponententrägermenge, danach über einen ausdrücklich eingeführten Indexzeugen in deren indizierte Vereinigung. Damit sind alle Voraussetzungen für die Graphsätze belegt. Die Zugehörigkeit zur indizierten Vereinigung ist als eigene Notationsdefinition ausgeschrieben.

Sämtliche Funktionsextensionalitätsschlüsse nennen beide Funktionstypen, die gemeinsam verwendete Definitionsmenge und die durch Implikations- und Allquantoreinführung bewiesene punktweise Gleichheit. Mehrere beschränkte Quantoren werden einzeln und in der richtigen Reihenfolge eingeführt. Für umgekehrte Gleichheitssubstitutionen stehen tatsächliche Symmetriezeilen im Beweis, keine verschachtelten Theoremverweise innerhalb von Gleichheitseliminationen.

Beim binären Produkt werden zwei beziehungsweise drei beliebige Produktmitglieder jeweils durch getrennte erste und zweite Komponentenzeugen zerlegt. Die Komponentenbedingungen werden per Konjunktionselimination zugänglich gemacht; nach dem komponentenweisen Rechnen entfernen vier beziehungsweise sechs Existenzeliminationen sämtliche Zeugen, bevor die Allquantoren eingeführt werden. Die für die verschachtelten Produktdefinitionen nötigen Zwischenprodukte sind typisiert.

Validierung: Sämtliche neuen numerischen Verweise liegen vor ihrer Benutzung; der globale Schrittindexscan meldet weiterhin nur die 35 bereits dokumentierten Makrofortsetzungs-Blindstellen und keine Stelle aus den neuen Produktbeweisen. Alle verwendeten Referenzen lösen sich mit dem tatsächlichen Lua-Normalisierer auf; neue lokale IDs werden durch die zusätzlichen Definitions- und Hilfsteile registriert. Die Theoremdeklarationen vor und nach dieser Änderung wurden parsergestützt exakt verglichen. Die mathematischen Schlussrichtungen und Eigenvariablenbedingungen wurden direkt geprüft; dies ist kein maschinell verifiziertes Beweissystem.

Belege: `b28-product-final.json`, `b28-product-final-preview.tex`, `b28-product-final-refcheck.lua`, `b28-products-applied.json`, `b28-products-own.diff`. Die Ausgangskopie unmittelbar vor Einfügung heißt `b28-products-before.tex`. Keine Builds gestartet und keine PDFs verändert.
