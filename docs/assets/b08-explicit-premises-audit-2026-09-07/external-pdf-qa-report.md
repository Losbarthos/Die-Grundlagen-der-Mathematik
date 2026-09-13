# Visuelle Prüfung der externen B08-Anwendungen

Alle **70** migrierten Anwendungen und Zitate der acht betroffenen Einzelbände und der Übersicht wurden auf **46** physischen Zielseiten visuell geprüft. Die geänderten Begründungen und Übersichtsanzeigen sind vollständig lesbar, passend umbrochen und ohne Überlagerung oder Abschneidung. Nach der Prüfung wurde ausschließlich der unten genannte benachbarte Formelumbruch mit Root abgestimmt und ergänzt. Die Nachprüfung schloss zusätzlich die Folgeseite 184 von B28 ein.

Die Zielseiten wurden nicht aus Stichworttreffern geraten: Die stabilen IDs wurden über die aktuelle B08-Registry und AUX in PDF-Ziele aufgelöst. Anschließend wurden die tatsächlichen externen GoToR-Linkannotationen der frisch gebauten Einzelbände abgeglichen. Für jede Ziel-ID stimmen die Annotationszahlen exakt mit dem semantischen Quelleninventar überein. Gerendert wurde mit `pdftoppm`, alle unten aufgeführten PNGs wurden angesehen. SHA256 und PDF-Zeitstempel stehen in den JSON-Inventaren.

| Band | Anwendungen/Zitate | Physische PDF-Seiten (Druckseite jeweils minus 1) | Befund |
| --- | ---: | --- | --- |
| B00 | 3 | 22 | Geänderte Stellen sauber |
| B09 | 2 | 19 | Geänderte Stellen sauber |
| B10 | 6 | 27, 32, 33, 70, 71 | Geänderte Stellen sauber |
| B11 | 2 | 10, 13 | Geänderte Stellen sauber |
| B20 | 6 | 28, 32, 91, 102 | Geänderte Stellen sauber |
| B21 | 3 | 17, 67, 71 | Geänderte Stellen sauber |
| B28 | 45 | 98, 118, 120, 121, 124, 125, 126, 127, 128, 129, 157, 158, 165, 177, 178, 183, 186, 188, 189, 194, 202, 204, 209, 212, 213, 217, 219 | Geänderte Stellen sauber |
| B37 | 1 | 23 | Geänderte Stellen sauber |
| B43 | 2 | 21, 51 | Geänderte Stellen sauber |

## Besonders geprüfte B28-Stellen

Alle acht Beweiszeilen mit ergänzten Konjunktionsprojektionen bzw. zwei durch ∧I verbundenen Einzelanwendungen sind sauber: Quellzeilen 289/290, 326/327, 363/364, 3023 und 3030; physische PDF-Seiten 126–129, 188–189. Die beiden Doppelanwendungen sind vollständig sichtbar und korrekt in der Begründungsspalte umbrochen.

Alle sieben Vierprämissen-Anwendungen von `MutuallyInverseFunctionBijection` sind lesbar: Quellzeilen 1755, 2190, 2943, 3523, 3684, 3831 und 4031; physische Seiten 158, 165, 186, 204, 209, 213 und 219. Auch die längsten vier Projektionsargumente auf Seiten 186 und 219 sind vollständig sichtbar. Diese sieben Aufrufe liegen sämtlich in B28; in B20 gibt es keinen solchen Aufruf.

## Benachbarter Layoutrest

B28, physische Seite **183** (gedruckt **182**), Einheiten-Transport (`SemigroupIsoIdentitiesZerosUnits`), Beweisschritt **54**, `tex/B28-isomorphism-examples.tex:2809`: Die zweite Zeile der nach der Verweismigration unveränderten Äquivalenzformel lief in die Begründungsspalte. Nach Abstimmung mit Root wurde ein zusätzlicher Umbruch innerhalb der rechten Konjunktion ergänzt. Der gezielte Neubau bestand den Referenzaudit am 07.09.2026 um 17:41:04. Die Seiten 183 und 184 sind erneut visuell geprüft und sauber. Alle 45 B28-Ziele verbleiben auf ihren bisherigen Seiten; vier Linkrechtecke verschoben sich vertikal. Daher wurde zusätzlich die schon zuvor geprüfte Zielseite 186 erneut kontrolliert: ebenfalls sauber. Kein Layoutrest an den geänderten Stellen.

Die ursprüngliche Migrationsvalidierung bleibt als zeitlich früherer exakter Vergleich erhalten. Der spätere Darstellungswechsel verändert genau eine rohe TeX-Formelzeichenfolge; nach Entfernen der expliziten Layouttokens sind Vorher und Nachher exakt identisch. Alle 2327 Beweiszeilen, sämtliche Begründungen, Abhängigkeiten und Referenzargumente bleiben gleich. Der separate Beleg `external-layout-ledger.json` enthält Vorher/Nachher und den neuen Quellenhash; `external-layout.diff` und `B28-examples-before-external-layout.tex` sichern den Übergang.

## Übersicht und Abschluss

Die drei reinen Zitate und ergänzten Aussagevoraussetzungen in `tex/ueberblick/b08.tex` stehen auf physischer Seite 22 der Übersicht (Druckseite 21). Alle drei Bijektivitätsvoraussetzungen, Umkehraussagen und Theoremnummern passen sauber in die rechte Tabellenspalte. Die Übersicht wurde erst nach `Reference audit passed: B00` in `build-main-publish.log` geprüft. Damit ist der beauftragte externe PDF-Prüfumfang vollständig abgeschlossen.

Belege: `pdf-external-qa/Bxx-targets.json` enthalten Einzelzuordnung Quelle/Zeile/Schritt/Argumente/PDF-Rechteck. `pdf-external-qa/report.json` fasst alle Zielseiten und PDF-Hashes zusammen.
