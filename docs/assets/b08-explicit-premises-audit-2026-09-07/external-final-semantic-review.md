# Abschließende semantische Prüfung der 70 externen B08-ID-Aufrufe

Ergebnis: **70 Aufrufe vollständig inventarisiert; keine weitere Quellenkorrektur erforderlich.** Es handelt sich um 66 Beweisanwendungen und vier reine Quellenverweise. Die Prüfung verwendet die endgültigen Prämissenreihenfolgen aus `tmp/b08-explicit-premises/inverse-migration.json` und `composition-migration.json`.

Die Beweisanwendungen umfassen 59 Anwendungen der Umkehrsätze und sieben Anwendungen von `MutuallyInverseFunctionBijection`. Für jede Anwendung stehen in `final-semantic-review.json` die endgültige Satzformel, geforderte Anzahl der Prämissen, tatsächliche Argumentliste, aus den Belegzeilen gewonnene Einzelformeln und die Schlusszeile. Bei ∧E-Argumenten wurde die betreffende Komponente tatsächlich aus der angegebenen Konjunktionszeile ermittelt.

Alle 59 Anwendungen der Umkehrsätze zitieren als erste Prämisse eine ausdrückliche Bijektionsaussage für die richtige Funktion mit den richtigen Trägermengen. Die Elementprämissen liegen jeweils in der erforderlichen Quell- oder Zielmenge. Die beiden Anwendungen der Eindeutigkeit verwenden außerdem den richtig gerichteten Funktionstyp und die passende beschränkte Umkehrgleichung. Eine bloße Isomorphismusannahme oder passende Argumentanzahl wurde nicht als ausreichender Beleg gewertet.

Die 37 Umkehr-Anwendungen in B28 wurden zusätzlich von Agent15 unabhängig geprüft; siehe `tmp/b08-explicit-premises/b28-inverse-application-review.md` und `.json`. Die übrigen Anwendungen wurden anhand ihrer konkreten Formeln kontrolliert. In B09 steht `k_y` gemäß der ausdrücklichen Abkürzung vor dem Beweis für `φ⁻¹(s(y))`. In B21 wird die erhaltene Gleichung `λ_n(λ_n⁻¹(j))=j` in derselben Beweiszeile zusätzlich mit der ausdrücklich zitierten Definition von `λ_n` als `λ_n⁻¹(j)+1=j` geschrieben. Beide Schreibweisen benötigen keine weitere Bijektionsprämisse.

## Die sieben Anwendungen der gegenseitigen Umkehrbarkeit

Die endgültige Reihenfolge lautet `G:A→B`, `F:B→A`, `F∘G=Id_A`, `G∘F=Id_B`; der Schluss besagt, dass `F:B→A` bijektiv ist. Alle sieben Anwendungen stehen in `tex/B28-isomorphism-examples.tex`.

| Aktuelle Quellzeile | Schlussfunktion | Tatsächliche vier Argumente | Prüfung |
|---:|---|---|---|
| 1755 | Komponentenabbildung `F` | `14,11,65,40` | Gegenläufige Produkttypen; beide Identitäten in richtiger Reihenfolge |
| 2190 | `F:S→T` | `4,3,6,5` | Erst `G:T→S`, dann `F:S→T`; anschließend `F∘G=Id_T` und `G∘F=Id_S` |
| 2943 | `f` auf den frisch erweiterten Trägern | `∧E₂(15),∧E₁(15),∧E₂(22),∧E₁(22)` | Beide Typen und beide Gleichungen einzeln aus den passenden Konjunktionen entnommen |
| 3523 | `C_f` | `∧E₂(27),∧E₁(27),83,55` | Erst `C_h`, dann `C_f`; Kompositionsgleichungen haben die erforderlichen Träger |
| 3684 | `Φ` auf den Unterstrukturfamilien | `∧E₂(34),∧E₁(34),59,47` | Erst `Ψ`, dann `Φ`; beide Identitäten stimmen mit den Familien überein |
| 3831 | `Θ` auf den Kongruenzfamilien | `∧E₂(15),∧E₁(15),47,32` | Erst `Λ`, dann `Θ`; beide Identitäten stimmen mit den Kongruenzträgern überein |
| 4031 | `Φ(α)=f∘α` auf den Lösungsmengen | `∧E₂(50),∧E₁(50),∧E₂(77),∧E₁(77)` | Erst `Ψ`, dann `Φ`; die beiden Identitäten werden in der erforderlichen Reihenfolge projiziert |

Bei der letzten Anwendung verwendet die Schlussformel die bereits definierte Wertzuordnung `α↦f∘α` anstelle des lokalen Namens `Φ`. Die Typisierung sowie die Identitätsgleichungen wurden für genau diese Zuordnung geprüft. Die frühere allgemeinere Term-/Systembeweislücke wird durch diesen korrekten Bijektivitätsschluss aus den angegebenen Prämissen nicht als geschlossen bezeichnet.

Die vier Aufrufe ohne Beweisargumente sind reine Quellenverweise: drei in der B08-Übersicht und einer im Fließtext von B28 auf `MutuallyInverseCompanionBijection`. Sie sind keine argumentlosen tabellarischen Anwendungen und verlangen daher keine künstlichen Schrittargumente.

## Abschließende Suche nach alten Zielen

Der erneute read-only Gesamtcheck erfasst **110 aktive Quellen einschließlich der aktuellen B08-Hauptquelle** und **19.555 tatsächliche Formelverweise**. Gegen die eingefrorene Vorher-Registry und den tatsächlichen Lua-Normalisierer findet er **keinen verbleibenden Aufruf auf eines der 26 geänderten alten B08-Ziele**. Das vollständige Ergebnis steht in `remaining-old-targets-including-b08.json`. Die Übersicht und alle aktiven Includes sind dabei enthalten; Archive bleiben ausgeschlossen.

Die Prüfung betraf Prämissenanzahl, konkrete Belegformeln, Richtung der Abbildungen und Kompositionsgleichungen sowie die vollständige Schlüsselmigration. Sie ist kein allgemeiner maschineller Beweisprüfer. In diesem abschließenden Review wurden keine Quellen geändert und keine LaTeX-Builds ausgeführt.
