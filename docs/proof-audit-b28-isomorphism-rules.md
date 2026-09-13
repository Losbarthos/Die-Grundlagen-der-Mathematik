# Band 28: Isomorphismen und Tabellenbeweise

Stand: 6. September 2026. Dieser Bericht dokumentiert die inhaltliche Ergänzung und die lokale Quellprüfung. Die Gesamtkompilation und die visuelle PDF-Prüfung erfolgen im übergeordneten Arbeitslauf.

## Neue Sammlung

`Bd. 28 - Halbgruppen.tex` bindet vor dem Abschnitt über das Isomorphieproblem für Potenzhalbgruppen die Datei `tex/B28-isomorphism-examples.tex` ein. Sie enthält den Abschnitt „Beispiele von Isomorphismen“. Die zusätzlichen Konstruktionen werden im Abschnitt definiert; bereits vorhandene Aussagen werden unter ihren stabilen Schlüsseln verwendet.

Die wesentlichen Satzschlüssel sind:

| Schlüssel | Inhalt |
| --- | --- |
| `SemigroupIsoInverse` | Umkehrisomorphismus |
| `SemigroupIsoElementaryTransport` | Bilder, Urbilder und elementare Trägereigenschaften |
| `SemigroupIsoSubstructureTransport` | Unterhalbgruppen sowie Links-, Rechts- und zweiseitige Ideale; beide Richtungen |
| `SemigroupIsoClosedCarrierRestriction` | Einschränkungen auf abgeschlossene Träger, auch leere |
| `SemigroupIsoPositiveCarrierPowers` | Produktpotenzen des Trägers und die eingeschränkten Isomorphismen |
| `SemigroupIsoGeneratedSubsemigroups` | Erzeugte und monogene Unterhalbgruppen |
| `SemigroupIsoPrincipalIdealsAndGreen` | Hauptideale und Green-Relationen |
| `SemigroupIsoFinitePowerSemigroups` | Endliche nichtleere Potenzhalbgruppen |
| `SemigroupIsoDirectProducts` | Direkte Produkte, Umindizierungen und kartesische Potenzen |
| `SemigroupCanonicalProductIsomorphisms` | Vertauschung, Umklammerung, einpunktiger Faktor, Exponentengesetz und Verteilung einer kartesischen Potenz über ein Produkt |
| `SemigroupIsoOpposite` | Opponierte Halbgruppen |
| `SemigroupIsoCentralizers` | Zentralisatoren und Zentren |
| `SemigroupIsoLocalCarriers` | Lokale Träger `eAe` bei idempotentem `e` |
| `SemigroupIsoIdentitiesZerosUnits` | Neutrale Elemente, Nullelemente und Einheiten |
| `SemigroupIsoFreshAdjunctions` | Adjunktion eines neuen neutralen Elements oder Nullelements |
| `SemigroupIsoCongruenceQuotients` | Transportierte Kongruenzen und Quotienten |
| `SemigroupIsoReesQuotients` | Rees-Quotienten |
| `SemigroupIsoEndomorphismConjugation` | Endomorphismen und Automorphismen unter Konjugation |
| `SemigroupIsoSubstructureOrders` | Ordnungsisomorphismen der Unterstrukturen |
| `SemigroupIsoEquationSolutionTransport` | Termauswertung und Lösungsmengen von Gleichungen |

Die neue Datei umfasst 1.392 gezählte Beweisschritte in 75 Beweisteilen. Langzeilige Begründungen verwenden dieselbe rechte Spalte wie die übrigen Tabellen. Die Sätze werden mit ihren benötigten Voraussetzungen in eigenständigen Prämissenzeilen angewendet.

## Mathematische und formale Prüfung

- Produktpotenzen `A^n` und kartesische Potenzen werden ausdrücklich unterschieden.
- Nichtleerheitsannahmen der positiven Produktpotenzen sind in den Abhängigkeiten enthalten. Der Induktionsanfang verwendet ausdrücklich `A^1=A` und den Satz `SemigroupSquareSubset` mit beiden Voraussetzungen.
- Leere Halbgruppen und leere direkte Produktträger sind mit der vorhandenen Definition verträglich. Für eine bereits vorgegebene Familie von Isomorphismen wird kein zusätzlicher Auswahlschritt benötigt.
- Das Relationsbild wird vor seiner Verwendung für jede Relation auf dem Quellträger definiert; die Kongruenzeigenschaft wird erst anschließend bewiesen.
- Die Aussagen zu Produkten, Erzeugnissen, Quotienten, Zentralisatoren, lokalen Trägern, Einheiten, Adjunktionen, Endomorphismen und Gleichungen wurden zusätzlich von einem zweiten Bearbeiter mathematisch gegengeprüft. Einzelheiten der zweiten Hälfte stehen in `docs/proof-audit-b28-constructions-qa.md`.

## Bestehender Hauptband

- Elf vorhandene lange Beweise wurden in sinnvolle Beweisteile gegliedert. Fortgesetzte Schrittzählungen sind explizit gesetzt.
- Sämtliche 174 echten geschachtelten Theorem-Aufrufe wurden in selbständige Prämissenzeilen ausgezogen und die Schrittverweise mit `scripts/proof-edit-tools.py` renummeriert. Der Zählwert umfasst auch Theorem-Aufrufe innerhalb logischer Regelargumente.
- Die Induktionsbeweise `SemigroupWordBlockLaw` und `SemigroupTreeNormalForm` leiten jetzt Basis und Schritt unter expliziten Annahmen ab, entladen diese und wenden erst dann das jeweilige Induktionsschema an.
- Die drei Äquivalenzteile der Zeugenbeschreibung dreifacher Mengenprodukte enthalten explizite Hin- und Rückrichtungen.
- Fünf durch eingefügte Prämissen unterbrochene Gleichheitsketten wurden geprüft und mit vollständigen linken Seiten beziehungsweise eindeutigen Kettenverweisen repariert. Im Einermengen-Rekonstruktionsbeweis bleibt die Annahme `a∈A` bis zur All-Einführung erhalten.
- Die lokale Umdefinition von `proofstepwidestar` wurde entfernt; `MogProofStepWideStarKeep` delegiert an das zentrale Tabellenmakro. Seine 14 Aufrufe werden deshalb bei der abschließenden Indexprüfung wie gewöhnliche nummerierte Schritte behandelt.
- `repair-wide-lhs.py 28 --write` und `align-proof-reasons.py 28 --write` wurden abschließend ausgeführt. Der typographische Lauf änderte 33 Zellen; beim zweiten Lauf waren keine weiteren Änderungen nötig.
- Die abschließende Quellprüfung fand keine echten geschachtelten Theorem-Prämissen und keine ungültigen numerischen Schrittverweise. Fünf zunächst angezeigte Kandidaten entfallen, sobald der Indexscanner das lokale Mog-Makro korrekt mitzählt.

Prüfspezifikationen und Hilfsskripte liegen gesammelt unter `tmp/proof-audit/b28/`; im Projektstamm verbleiben keine `tmp-b28-*`-Hilfsdateien.

## Gesondert beauftragte kleine Korrekturen

In Band 3 wurden ein mehrdeutiger Kettenschluss und die beiden Fälle des Existenzbeweises für den Prädikatdurchschnitt korrigiert. Die Fälle sind als `PredicateIntersectionExistsNonemptyCase` und `PredicateIntersectionExistsEmptyCase` registriert; die Existenz-Elimination im nichtleeren Fall ist explizit.

In Band 19 wurden die beiden Richtungen von `RealCutMembership` als `RealCutMembershipForward` und `RealCutMembershipBackward` registriert. Der Zusammenfassungsteil verweist auf diese benannten Aussagen und nicht mehr auf in einem anderen Beweisteil zurückgesetzte Schrittzahlen.
