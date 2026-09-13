# Unabhängige semantische Prüfung der B08-Umkehrtheoreme

Prüfer: `audit_b15_b27`, 2026-09-07. Geprüft wurden die elf neu formulierten Umkehrtheoreme aus `inverse-migration.json` einschließlich ihrer 81 Beweiszeilen sowie die beiden unveränderten Theoreme8.3.3.7 und8.3.3.11 mit zusammen22Beweiszeilen. Die aktuellen Anzeigen, Strukturargumente, Delta-Kontexte und vollständigen Begründungen wurden gelesen. Ergebnis: **alle13Theoreme bestehen die semantische Prüfung; kein Korrekturbedarf in den geprüften neuen Beweisen**.

## Iota-Schlüsse in8.3.3.5 und8.3.3.6

Band1, Abschnitt „Beschränkte Quantoren“ (um Zeile1000), identifiziert `∃!x∈A P(x)` ausdrücklich mit `∃!x(x∈A∧P(x))`. Die Iota-Konvention in Band1, Zeilen1257–1283, erlaubt nach bewiesener eindeutiger Existenz die Bezeichnung des eindeutigen Objekts durch den Iota-Term und die beidseitige Ersetzung durch das definierte Symbol.

In8.3.3.5 wird zunächst `F(x)∈B` und dann `∃!u∈A F(u)=F(x)` bewiesen. Die Prämissen1,3,4 der anschließenden Verwendung von `InverseFunctionDef` liefern daher genau die passende Bijektivität, Zielzugehörigkeit und eindeutige Existenz. Die Iota-Eigenschaft ist die Konjunktion `F⁻¹(F(x))∈A ∧ F(F⁻¹(F(x)))=F(x)`. Nach ∧E liegen beide Argumente im Definitionsbereich der ausdrücklich hergeleiteten Injektivität vonF. Der letzte Aufruf hat die passende Gleichheitsrichtung.

In8.3.3.6 liegt analog nach Schritt3 `∃!x∈A F(x)=y` vor. Der Definitionsaufruf mit1,2,3 liefert die Urbildkonjunktion; ∧E2 liefert die Rechtsumkehrung. Es wird kein neues Iota-Axiom vorausgesetzt. Das ist ein zulässiger Einsatz der bereits vorhandenen Iota-/Definitionskonvention, keine Schlussfolgerung allein aus dem Namen eines Satzes. Bei der Einsetzung vonF(x) wird der gebundene Urbildname zuu umbenannt; es entsteht keine Variablenbindung des freienx.

## Einzelbefunde

| Theorem | ID / Inhalt | Zeilen | Ergebnis |
| --- | --- | ---: | --- |
|8.3.3.1|`InverseFunctionType`|2|Bijektivität als explizite Annahme; Definitionsaufruf liefert den inversen Funktionstyp.|
|8.3.3.2|`InverseFunctionTotalRelation`|3|Explizite Bijektivität; Funktions-/Relationsschluss mit dem hergeleiteten Typ.|
|8.3.3.3|`InverseFunctionValue`|4|Bijektivität und Zielmitgliedschaft explizit; beschränkter Allquantor wird mittels ∀E und →E angewandt.|
|8.3.3.4|`InverseFunctionValueType`|4|Der inverse Funktionstyp und die Zielmitgliedschaft werden beide an den Typisierungssatz übergeben.|
|8.3.3.5|`InverseFunctionLeftInverse`|9|Passende eindeutige Existenz vor dem Iota-Schluss; beide Urbilder anschließend für die Injektivität typisiert.|
|8.3.3.6|`InverseFunctionRightInverse`|5|Passende eindeutige Existenz vor dem Iota-Schluss; korrekte Konjunktionselimination.|
|8.3.3.7|Bild des Urbilds einer Teilmenge|9|Y⊆B und Bijektivität bereits explizit. Einschränkungs- und Bildsatz erhalten ihre Typprämissen; Symmetrie und Transitivität sind passend gerichtet.|
|8.3.3.8|`InverseFunctionInjectiveCriterion`|11|F-Typ und beide inversen Argumenttypen vor der Anwendung auf gleiche Werte hergeleitet; der Drei-Gleichheiten-Satz passt exakt.|
|8.3.3.9|`InverseFunctionSurjectiveCriterion`|5|F(x) ist ein ausdrücklich typisierter Zielzeuge; ∃I erhält Zielmitgliedschaft und Linksumkehrgleichung als Konjunktion.|
|8.3.3.10|`InverseFunctionBijection`|11|Die zwei beschränkten Injektivitätsquantoren werden getrennt eingeführt; Annahmen5,4,3 werden innen nach außen entladen. Die Surjektivitätsannahme8 wird ebenfalls vor dem abschließenden Definitionsaufruf entladen.|
|8.3.3.11|Eigeninversität der Identität|13|Keine Zusatzprämisse nötig: Bijektivität und Typ vonIdA sind unbedingte vorhandene Sätze. Alle Gleichheitsersetzungen sind in zulässiger Richtung; Extensionalität erhält beide Typen und den Allsatz.|
|8.3.3.12|`InverseFunctionRightInverseUniqueness`|14|Bijektivität, TypG:B→A und Rechtsumkehrgleichung explizit. Beide verglichenen Urbilder liegen nachweislich inA; die lokale Annahme y∈B wird vor der Extensionalität entladen.|
|8.3.3.13|`InverseFunctionLeftInverseUniqueness`|13|Bijektivität, TypG:A→B und linke Gleichung explizit. Beide Argumente vonF⁻¹ liegen inB; die lokale Annahme x∈A wird vor der Extensionalität entladen.|

Die Gleichheitskette in8.3.3.8 verwendet genau `a=b, a=c, b=d ⊢ c=d` mit den Schritten8,9,10. Die beiden Eindeutigkeitssätze verwenden `a=b, c=b ⊢ a=c` in der passenden Richtung. In8.3.3.11 ist die Reflexivitätszeile eine gültige Grundlage für die gezielte einseitige Ersetzung zur Symmetrie; keine rückwärts angewandte =E-Regel ist nötig.

Die zunächst noch aus früheren Schlüsseln bestehenden internen Referenzen in 8.3.3.11 wurden inzwischen zentral migriert. Ihre sachlichen Prämissen stehen im Beweis bereits bereit. Sie sind kein neuer semantischer Befund.

## Statische Belege und Grenzen

`review-inverse-independent.py` bestätigt13Theoreme,81neue beziehungsweise103insgesamt geprüfte Zeilen, die Formeln der elf Mappingeinträge und keine ungültigen rein numerischen Schrittverweise. `inverse-independent-refcheck.lua` löst die externen/älteren Referenzformeln gegen die vorhandenen Band1–8-Registries auf und berücksichtigt die elf neuen lokalen IDs; es gibt keine fehlende Referenz in diesem Prüfmodell. Das ersetzt nicht den nach der Migration erforderlichen Build-/Referenzaudit.

Maschinenlesbares Ergebnis: `inverse-independent-review.json`. Der Prüfer hat keine Quelle verändert und keinen Build gestartet.

Nachtrag nach dem ersten B08-Build: Der ursprüngliche Registercheck prüfte das Vorhandensein der Schlüssel ohne Umgebungsfilter. Dadurch wurden fünf falsche Selektoren `[thm]` für das Injektivitätsaxiom in den gemeinsam geprüften Bereichen erst beim Build entdeckt und zentral zu `[ax]` korrigiert; zwei betrafen diesen Umkehrabschnitt. Formeln und Belegargumente blieben unverändert. Die Belege und Abschnittshashes wurden neu erfasst. Der zusätzliche `review-selectors-independent.py` prüft jetzt 200 tatsächliche Aufrufe aller drei Reviewbereiche einschließlich Selektor und aufgelöster Registerart: keine fehlenden, mehrdeutigen oder falsch typisierten Verweise. Vollständiger Beleg: `selector-aware-independent-review.json`.
