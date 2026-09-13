# Unabhängige Prüfung der sechs B37-Verweisreparaturen

Prüfer: `audit_b15_b27`, 2026-09-07. Vergleich gegen `before.tex`, gegen die aktuellen Definitionen in B38/B40 und gegen die tatsächliche Registrierung durch `FormulaDefDeltaR`.

Ergebnis: Die begrenzte Reparatur ist korrekt. Keine weiteren Quellenänderungen erforderlich; keine Builds gestartet.

Die lokale Monoiddefinition verlangt genau Halbgruppenstruktur, Trägerzugehörigkeit der Eins sowie beide auf den Träger beschränkten Neutralitätsgesetze. Dies entspricht `MonoidDef` aus B38. Die lokale Gruppendefinition ergänzt genau die Existenz eines beidseitigen Inversen für jedes Trägerelement; dies entspricht den definierenden Bedingungen von `GroupDef` aus B40. Die Definitionen sind vor sämtlichen neuen Verwendungen platziert. Das Makro `FormulaDefDeltaR` registriert allein sein zweites Pflichtargument als Strukturkey und ID, also die beiden eindeutigen lokalen Namen; die angezeigten Monoid-/Gruppenformeln werden nicht registriert. Daher entsteht durch diese Ergänzung keine Doppelregistrierung mit B38/B40 im Gesamtband.

Die sechs Gründe wurden einzeln gegen die genaue Klammerung der Definition gelesen:

- `CancellativeIdempotentGivesMonoid`, Schritt18: Die verschachtelte ∧I-Kette aus3,5,13,17 erzeugt exakt `Halbgruppe ∧ (e∈A ∧ (Linksneutralität ∧ Rechtsneutralität))`.
- `FiniteCancellativeMonoidIsGroup`, Schritt4: ∧E2, danach ∧E1 liefert aus3 genau `e∈A`.
- Derselbe Hilfsteil, Schritt16: dreimal ∧E2 liefert die rechte Neutralitätsformel; ∀E und →E mit6 liefert `x⋆e=x`.
- Derselbe Hilfsteil, Schritt17: zweimal ∧E2 und ∧E1 liefert die linke Neutralitätsformel; ∀E und →E mit6 liefert `e⋆x=x`.
- Derselbe Hilfsteil, Schritt24: ∧I aus3,23 bildet exakt das Definiens der lokalen Gruppendefinition. Der bereits vorliegende Schritt23 hat den beschränkten Allquantor korrekt mittels →I und ∀I eingeführt; der Inversenzeuge ist zuvor mit ∃E entladen.
- Im abschließenden Existenzteil, Schritt8: ∧E2 und ∧E1 liefern aus7 genau `e∈A` mit den angegebenen Annahmen2,6.

Alle referenzierten Schritte stehen vorher im jeweiligen Hilfsteil. Keine Zeile, Formel oder Annahmenabhängigkeit wurde bei der Reparatur hinzugefügt, entfernt oder umnummeriert. Der unabhängige Vergleich bestätigt 312 identische Formeln samt Abhängigkeiten und genau sechs geänderte Gründe. Die neuen Ketten enthalten keinen Gleichheitsschluss; bestehende Gleichheitsschlüsse der direkt umgebenden Inversenargumentation wurden mitgelesen und passen in der verwendeten Richtung.

Die dokumentierten größeren B37-Beweislücken außerhalb dieser sechs Gründe sind nicht Gegenstand dieser Prüfung und werden dadurch nicht als geschlossen bezeichnet.
