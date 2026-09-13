# Unabhängiger semantischer Review der B08-Kompositionsbeweise

**Bestanden:** alle 16 Theoreme des Abschnitts „Kompositionen und Inversen“, insgesamt 242 Beweiszeilen. Keine weiteren sachlichen Voraussetzungen fehlen. Keine Korrektur empfohlen; keine TeX-Änderungen oder Builds vorgenommen.

Die Prüfung erfolgte an der aktuellen Quelle nach Freigabe durch Agent01. Sie umfasste Aussage, Delta-Kontext, sämtliche Beweiszeilen, gerichtete Gleichheitsersetzungen, Typvoraussetzungen der Anwendungen und die Eigenvariablenbedingungen der Quantorregeln. Die bloßen Mengen- und Funktionsvariablendeklarationen im Delta-Kontext sind keine zusätzlichen mathematischen Voraussetzungen.

| Nummer | ID | Zeilen | Ergebnis |
| --- | --- | ---: | --- |
| 8.3.4.1 | BijectiveFunctionComposition | 30 | Beide Bijektivitäten ausdrücklich vorausgesetzt; die beiden Existenzzeugen werden getrennt entladen. |
| 8.3.4.2 | FunctionLeftIdentity | 11 | Funktionstyp, Identitätstyp und gemeinsame Typen für die Extensionalität vorhanden. |
| 8.3.4.3 | FunctionRightIdentity | 10 | Kompositionsargumente in der Reihenfolge innere Identität, äußeres F; Mitgliedsannahme entladen. |
| 8.3.4.4 | InverseFunctionRightComposition | 15 | Bijektivität und beide Funktionstypen vorhanden; Rechtsinverse und Gleichheitssymmetrie korrekt. |
| 8.3.4.5 | InverseFunctionLeftComposition | 15 | Bijektivität und beide Funktionstypen vorhanden; Linksinverse und Gleichheitssymmetrie korrekt. |
| 8.3.4.6 | InverseCompositionLeftInversePointwise | 20 | Beide Bijektivitäten und Elementvoraussetzung explizit; sämtliche Kompositions- und Inversenargumente passend. |
| 8.3.4.7 | InverseFunctionComposition | 14 | Bijektivität der Komposition zuerst bewiesen; Urbildmitgliedschaft explizit; Extensionalität korrekt. |
| 8.3.4.8 | BijectiveCompositionInnerInjectiveCriterion | 14 | Alle Struktur- und Elementvoraussetzungen explizit; gerichtete Gleichheitsersetzungen korrekt. |
| 8.3.4.9 | BijectiveCompositionOuterSurjectiveCriterion | 16 | Typisierter Bildwert als Existenzzeuge; ursprünglicher Urbildzeuge korrekt entladen. |
| 8.3.4.10 | BijectiveCompositionOuterInjectiveCriterion | 33 | Surjektivität von F explizit; zwei getrennte Urbildzeugen; Bildgleichheitssatz mit vollständigen Typ- und Elementbelegen. |
| 8.3.4.11 | BijectiveCompositionInnerInjective | 11 | Gleichheitsannahme und beide Mitgliedsannahmen getrennt entladen. |
| 8.3.4.12 | BijectiveCompositionOuterSurjective | 7 | Vollständiger Kriteriumsaufruf; Elementannahme vor der Allquantoreinführung entladen. |
| 8.3.4.13 | BijectiveCompositionOuterBijective | 14 | Funktionstyp aus Surjektivität von F; vollständige Kriterien; Quantorentladungen korrekt. |
| 8.3.4.14 | MutuallyInverseFunctionBijection | 13 | Beide Funktionstypen explizit; Identitätsgleichungen vor der Rückersetzung symmetrisiert; Komponentenargumente korrekt. |
| 8.3.4.15 | MutuallyInverseCompanionBijection | 5 | Funktionstypen und Identitätsgleichungen in der vertauschten Instanziierung richtig angeordnet. |
| 8.3.4.16 | MutuallyInverseFunctionEquality | 14 | Bijektivität von F zuerst bewiesen; punktweise Rechtsumkehrung bewiesen und verallgemeinert; Eindeutigkeit korrekt instanziiert. |

Die Definitionsaufrufe wurden insbesondere mit `CompositionDef` und `FunctionExtensionality` in Band 5 abgeglichen. Die Kompositionsdefinition erwartet zuerst den inneren und dann den äußeren Funktionstyp; alle überprüften Aufrufe entsprechen dem. Die Extensionalität erhält jeweils zwei Funktionen mit derselben Definitions- und Zielmenge sowie die genaue beschränkte Gleichheitsmatrix.

`review-composition-independent.py` prüft zusätzlich unabhängig die 16 IDs, die anfänglichen Annahmen gegen die neuen Sequenzprämissen, alle 242 numerischen Belegabhängigkeiten einschließlich Entladungen und die endgültigen Abhängigkeitsmengen. Alle 14 verwendeten bereits registrierten Referenzschlüssel lösen sich in den Registern der Bände 1–8 auf; die neuen lokalen IDs werden aus den beiden aktuellen Migrationstabellen berücksichtigt. Die Regeln wurden darüber hinaus inhaltlich geprüft; der mechanische Abhängigkeitscheck allein beansprucht keinen vollständigen logischen Beweischeck.

Der maschinenlesbare Beleg `composition-independent-review.json` enthält den Abschnittshash und das vollständige Zeileninventar. `composition-independent-refcheck.lua` dokumentiert den begrenzten Registerabgleich.

Nachtrag nach dem ersten B08-Build: Der ursprüngliche Registercheck prüfte Schlüssel ohne Umgebungsfilter. Die dabei nicht erkannten falschen `[thm]`-Selektoren des Injektivitätsaxioms in 8.3.4.8 und 8.3.4.10 sind zentral zu `[ax]` korrigiert; Formeln und Belegargumente blieben unverändert. Zeileninventar und Abschnittshash wurden aktualisiert. Der zusätzliche `review-selectors-independent.py` prüft alle 200 tatsächlichen Aufrufe der drei Reviewbereiche einschließlich Selektor und Registerart fehlerfrei; Beleg: `selector-aware-independent-review.json`.
