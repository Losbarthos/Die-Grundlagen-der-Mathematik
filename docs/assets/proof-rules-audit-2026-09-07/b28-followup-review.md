# Unabhängige B28-Nachprüfung und ergänzende Korrekturen

Stand: 2026-09-07. Bearbeitet wurde ausschließlich `tex/B28-isomorphism-examples.tex`, jeweils aus der unmittelbar vorher erneut eingelesenen aktuellen Fassung. Keine eigenen Builds. Die übrigen Agenten bearbeiteten andere Teilbeweise derselben Datei. Vor jedem Schreiben wurde geprüft, dass sich die Datei während der Vorbereitung nicht geändert hatte. Ein Vergleich mit ausgeblendeten bearbeiteten Teilbeweiskörpern bestätigt, dass Anzeigen, Strukturargumente, Satzschlüssel und alle anderen Teile unverändert blieben.

## Gleichheitsrichtungen aus Root-Stufe 3 und benachbarter Transport

16 bearbeitete Zeilenstellen; Inventar `b28-equality-review-changes.json`, Ausgangsfassung `b28-equality-review-before.tex`.

- `SemigroupIsoImageMembership`: Aus `x=z` und `z∈U` war die Gleichheitselimination rückwärts benutzt. Explizites `z=x` mit dem bewiesenen Symmetriesatz eingefügt, anschließend richtige =E. Existenzelimination und Folgeschritte neu nummeriert.
- `SemigroupIsoInverseImageMember`: Ebenso `u=f(h(u))` vor dem Transport von `u∈f[U]` eingefügt.
- `SemigroupIsoClosedCarrierImage`: Symmetrie von `h(x⋄y)=h(x)⋆h(y)` eingefügt. Den Bildmitgliedschaftssatz zunächst mit seiner tatsächlichen Matrix `h(x⋄y)∈h[f[U]]` angewendet und danach `h[f[U]]=U` eingesetzt. Die Rückrichtung benötigt `↔E₂`, nicht `↔E₁`.
- `SemigroupIsoImageCarrierData`: Die neu eingeführte =E zur Nichtleerheit ist bereits richtig gerichtet. Die Schlusskonjunktion wurde jedoch linksassoziiert aufgebaut, während die folgenden Zugriffe rechtsassoziieren; nun `∧I(10,∧I(14,29))`.
- `SemigroupIsoEqualityReflection`: Dem Funktionskongruenzschritt fehlte die reflexive Ausgangsgleichung; nun `=E(5,=I)`.
- Die vier Rücktransporte für UHGr/LId/RId/Id verwenden jetzt die tatsächlichen beiden Konjunktionseliminationen.
- Die bereits vorwärts gerichteten iterierten =E-Schlüsse bei Umkehrabbildung und Bildabschluss sind explizit verschachtelt. Die Kurznotation ist inzwischen in Band 1 dokumentiert; diese vier Änderungen sind Klarstellungen der Reihenfolge.

Root-Stufe 2 führt keine neuen =E-Schlüsse ein. Die quantifizierten Matrizen wurden bereits in `b28-ui-independent-review.md` geprüft. Produkt-/Potenzbefunde wurden zunächst weitergegeben und anschließend auf ausdrücklichen Auftrag selbst korrigiert (siehe unten).

## Quotienten: wirkliche Vertreterelimination vor ∀I

`SemigroupQuotientIsSemigroup` enthält jetzt 74 statt 26 Zeilen. Getrennte Voraussetzungen und Klassenvergleichsschritte begründen die Wohldefiniertheit. Für Abschluss und Assoziativität werden für jede beliebige Klasse eigene Vertreter durch `QuotientRepresentative` beschafft. Die jeweiligen Annahmen sind exakt `a∈A ∧ X=[a]ρ`; Mitgliedschaft und Gleichheit werden einzeln eliminiert. `EqClassInQuotient`, die Quotientenoperationsdefinition, notwendige Gleichheitssymmetrien und =E liefern die jeweilige punktweise Matrix. Jede Vertreterannahme wird per ∃E entlassen; erst danach werden die getrennten Klassenmitgliedschaften per →I/∀I geschlossen.

Der abschließende Teil `SemigroupIsoCongruenceQuotients / Operationserhaltung` enthält jetzt 45 statt 19 Zeilen. Er verwendet dieselbe explizite Vertreterführung. Die ehemalige Mehrfachgleichung wurde in konkrete Gleichheiten und gerichtete =E-Schritte zerlegt. Die vorgeschriebene Klassenabbildung `bar f([a]ρ)=[f(a)]f*ρ` besitzt hier keinen eigenen registrierten Definitionsschlüssel; die drei Werte bei a, b und ab bleiben daher ausdrücklich als vorhandene Definitionsgleichungen bezeichnet. Keine neue Regel oder fiktive Referenz wurde eingeführt. Die benötigten Typen werden davor einzeln nachgewiesen.

Ausgangsfassung: `b28-quotient-quantifiers-before.tex`. Vollständige neue Körper: `b28-quotient-quantifiers-bodies.json`. Erzeugungsskript: `fix_b28_quotient_quantifiers.py` (nicht ungeprüft erneut ausführen).

## Potenzen und Endlichkeitsinduktion

18 bearbeitete Zeilenstellen in fünf Teilbeweisen; Inventar `b28-powers-finite-directions-changes.json`, Ausgangsfassung `b28-powers-finite-directions-before.tex`.

- `SemigroupCarrierPowersSubsemigroups`: Die drei verschachtelten Definitions-/Symmetrieverweise sind eigenständige Zeilen. Die Trägerdaten werden als Konjunktion geholt, Teilmenge und Nichtleerheit einzeln abgeleitet (einschließlich Symmetrie der Ungleichheit). Der Produktabschluss verwendet zwei getrennte Elementannahmen, `PowerSemigroupProductContains`, =E, Teilmengenelimination und richtige →I/∀I. Die abschließende Konjunktion wird rechtsassoziiert aufgebaut.
- `Elementpotenzen und Monogene`: Basisgleichung mit reflexiver Ausgangsformel und Symmetrie der Ziel-Potenz-eins-Gleichung. Im Schritt werden die beiden Nachfolgergleichungen ausdrücklich symmetrisiert und die tatsächliche Induktionsgleichung verwendet; die bisher zitierte Zeile 15 war lediglich die Sammelkonjunktion. Die Typisierungsschritte hängen nicht mehr unnötig von der Induktionsgleichung ab.
- `SemigroupFiniteSetProductBase` und `SemigroupFiniteSetProductStep`: Die Gleichheiten zur leeren Menge bzw. zur Vereinigung wurden vor Transport der Endlichkeit ausdrücklich umgedreht.
- `Endlichkeitsinduktion`: Für `P(∅)` eine eigene Annahme `∅⊆A`, Anwendung des Basissatzes und tatsächliches →I. Die beiden Zugriffe aus `U∪{a}⊆A` verwenden bestehende Mengensätze. Vor Modus ponens wird P(U) aus der Sammelannahme korrekt extrahiert.

## Verifikation und verbleibende Grenzen

`check_b28_own_parts.py` / `b28-own-parts-checks.json` prüfen die sieben zuletzt bearbeiteten Körper mit insgesamt 231 Zeilen. Numerische Verweise sind aufgelöst; Abhängigkeitsmengen der formal nachvollziehbaren Regelbäume stimmen. Beim Endlichkeitsinduktionsaxiom muss die Entladung der Induktionsannahme gesondert berücksichtigt werden; die einfache Vereinigungsprüfung markiert diese Stelle erwartungsgemäß zur manuellen Prüfung. Die Quantorenreihenfolge und Eigenvariablenbedingungen der neuen Vertreterbeweise wurden manuell geprüft.

Keine vollständige Formalisierung der verbleibenden ursprünglichen Prosa wird behauptet. In `SemigroupCarrierPowersSubsemigroups` verbleiben Produktmonotonie (Schritt 12), Instanziierung bei n+k (23) und Instanziierung bei k=n samt n+n=2n (27). Für letztere sind außerdem die positiven/natürlichen Typen nachzutragen. In `SemigroupFiniteSetProduct` verbleiben die ursprüngliche Konstruktion der Abbildung lambda_a sowie die beiden Mengengleichheitsargumente. Diese Stellen wurden dem koordinierenden Agenten ausdrücklich gemeldet. `SemigroupIsoQuotientBijection` enthält weiterhin die eigenständigen ursprünglichen Argumente für die Konstruktion und Bijektivität der Klassenabbildung; es war nicht Teil der direkten ∀I-Nachkorrektur.

Die erste B28-Ausgabe des koordinierten Vollbaus wurde auf physischen Seiten 188–190 und 192–193 geprüft. Die neuen Quotientenbeweisformeln und Quantorschlüsse sind gut lesbar. Drei ungebrochene Texte „Definitionsgleichung von bar f“ waren je 24,36 pt überbreit; die Begründungen wurden danach in die normale umbrechende Begründungsbox gesetzt. Der zu lange Teilbeweistitel „Wohldefiniertheit und Bijektivität der Klassenabbildung“ kollidierte mit seiner rechten Nummer und wurde zu „Bijektive Klassenabbildung“ gekürzt; sein Registrierschlüssel bleibt unverändert. Beide Layoutkorrekturen erfordern den vom Root koordinierten B28-Nachbau.

## PDF-Stichprobe vor zentralem KR-Umbruchpatch

Mit Poppler gerendert und visuell geprüft: B05 physische Seite 55 (gedruckt 54), B08 physische Seiten 78–79 (gedruckt 77–78), B10 physische Seite 206 (gedruckt 205). Nummerierte Familien, Umbrüche und Umlaute fehlerfrei. Insbesondere ist die B08-Fallwertformel innerhalb des Satzspiegels. PNGs und Textauszüge liegen in `tmp/pdfs/theorem-numbering-qa/`. Der danach zentral eingeführte KR-Minipage-Patch erfordert eine erneute B05/B10-Stichprobe nach dem vom Root koordinierten Neubau; diese älteren Bilder werden nicht als QA der späteren Fassung ausgegeben.
