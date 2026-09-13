# Unabhängige Prüfung der vier neuen B28-Beweisteile

Geprüft wurden ausschließlich die aus `root-b28-local.py`, `root-b28-units.py`, `root-b28-neutral.py` und `root-b28-unittransport.py` erzeugten Beweise sowie auf ausdrückliche Anweisung die sichtbare Matrix des zugehörigen Haupttheorems.

| Teil | geprüfte Zeilen | Ergebnis |
| --- | ---: | --- |
| SemigroupLocalCarrierStructure | 55, nach Korrektur 56 | Abschließenden Kriteriumsschluss explizit über das Bikonditional geführt |
| SemigroupUnitCarrierStructure | 43 | Keine Korrektur erforderlich |
| SemigroupIsoIdentityZeroConditions | 80 | Keine Korrektur im Beweis erforderlich; sichtbare Hauptaussage auf dieselbe Gleichungsrichtung präzisiert |
| Abschluss und Transport der Einheiten | 89, nach Ergänzung 90 | Gemeinsame e,z-Prämisse ausdrücklich gebildet; abschließende Neutralitätsannahme per Implikationseinführung entladen |

## Tatsächliche Korrekturen

1. `SemigroupSubsemigroupCriterion` folgert ein Bikonditional und nicht unmittelbar die Unterhalbgruppenbehauptung. Die neue Zeile 55 schreibt dieses Bikonditional aus der Halbgruppenprämisse aus; Zeile 56 erhält die Behauptung mit `\rRE{\rLREb{55},54}`.
2. Der Einheiten-Transport ruft den gemeinsamen Hilfssatz über e und z nur für die neutrale Bedingung auf. Die Instanz z=e wird jetzt durch `\rAI{2,2}` als gemeinsame Zugehörigkeitsprämisse ausdrücklich belegt.
3. Die sichtbare KR-Anzeige von `SemigroupIsoIdentitiesZerosUnits` verwendet jetzt `ex=x\land xe=x` und `zx=z\land xz=z` sowie die entsprechend gerichteten Zielgleichungen. Das stimmt genau mit den bewiesenen Hilfsteilmatrizen überein. Das Original-Strukturargument einschließlich der bisherigen Gleichheitsketten und die ID sind unverändert erhalten.

4. Der abschließende Isomorphismus stand zunächst noch unter Annahme 3 (Neutralität). Bei der anschließenden Kontrolle der Hauptkonklusion (iii) wurde diese zuvor übersehene fehlende Entladung erkannt. Neue Zeile 90 führt mit `\rRI{3,89}` die behauptete Implikation ein; nur die Voraussetzungen 1 und 2 bleiben offen. Die sichtbare Aussage (iii) verwendet jetzt dieselbe explizite Allquantorformel für die Neutralität und dieselbe objektsprachliche Implikation wie der Beweis. Das Original-Strukturargument bleibt erhalten.

## Mathematische und regelbezogene Prüfung

- Die Gleichheitssubstitutionen ersetzen jeweils die linke durch die rechte Seite der verwendeten Gleichheit. Selektive Ersetzungen gleicher Teilausdrücke sind zulässig; insbesondere sind die lokalen Schritte zur Darstellung `e=(ee)e` sowie `(e(uv))e=uv` korrekt.
- Im lokalen Träger wird der Zeuge a vor der Allquantoreinführung entladen. Die späteren u/v-Annahmen sind eigenständige Annahmen; beide werden vor dem Abschlusssatz einzeln entladen.
- Die Einheitenschließung verwendet als inversen Zeugen die umgekehrte Produktreihenfolge v' u'. Sämtliche für die Assoziativität benötigten Komponenten und Zwischenprodukte sind typisiert. Die beiden inversen Zeugen werden jeweils per Existenzelimination entfernt.
- Der Transport neutraler Elemente und Nullen benutzt den inversen Funktionswert nur nach nachgewiesener Zugehörigkeit zum Urbildträger. Vorwärts- und Rückwärtsimplikationen haben genau die jeweils behaupteten rechten Konstanten beziehungsweise Variablen. Die Allquantoreinführungen betreffen keine freie Variable einer verbleibenden Annahme.
- Der Einheitentransport erhält das invertierbare Paar durch zwei Gleichheitsreflexionen, transportiert Existenzzeugen in beiden Richtungen und beweist die Bildmengengleichheit aus zwei Mitgliedschaftsimplikationen. Der letzte Einschränkungsschluss verwendet die bereits nachgewiesene Teilhalbgruppenstruktur und anschließend die gerichtete Bildgleichheit. Danach wird die Neutralitätsannahme ausdrücklich entladen.
- Die globale Abkürzung h=f^{-1} ist am Anfang der Beispieldatei ausdrücklich festgelegt.

Alle in diesen vier Teilen benutzten Referenzen wurden zusätzlich mit dem tatsächlichen Lua-Normalisierer gegen die Registries aufgelöst; keine fehlende Referenz. Das ersetzt keine maschinelle Beweisprüfung: Die inhaltlichen Schlussrichtungen und Nebenbedingungen wurden direkt an den Formeln geprüft.

Belege: `root-b28-review-inventory.json`, `root-b28-review-changes.json`, `root-b28-review-refcheck.lua`; die vier Ausgangskörper heißen `root-review-*-before.tex`. Keine Builds gestartet und keine PDFs verändert.
