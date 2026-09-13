# PDF-QA der 16 B08-Kompositionssätze

**Endkontrolle bestanden. Keine offenen Layoutbefunde im geprüften Kompositionsabschnitt.**

Erster geprüfter PDF-Stand: `registry/_B08.pdf`, SHA256 `7e1166a68896667abbdd6eec19fa63dcc77a7fd9c6ca6dba6115cd530a4797ff`.

Alle 16 Sätze 8.3.4.1–8.3.4.16 und ihre 242 Beweiszeilen wurden auf den physischen Seiten 21–31 visuell geprüft. Die PNGs liegen unter `pdf-qa/composition-21.png` bis `pdf-qa/composition-31.png`. Die Fortsetzung des letzten Beweises auf Seite 31 ist vollständig enthalten. Keine abgeschnittenen Formeln, fehlenden Zeichen oder unaufgelösten Referenzen festgestellt.

## Abschließende lokale Fixliste dieses ersten PDF-Stands

| Ziel | Physische Seite | Befund | Empfohlene lokale Korrektur |
| --- | ---: | --- | --- |
| InverseCompositionLeftInversePointwise, 8.3.4.6, Schritt 15 | 25 | Formel stößt unmittelbar an die Begründung; Abstand laut Textbbox 0 pt. | Gleichung innerhalb derselben Beweiszeile umbrechen. |
| InverseCompositionLeftInversePointwise, 8.3.4.6, Schritt 16 | 25 | Nur 0,848 pt Abstand zur Begründung. | Gleichung innerhalb derselben Beweiszeile umbrechen. |
| InverseFunctionComposition, 8.3.4.7, Schritt 10 | 25 | Formel stößt unmittelbar an die Begründung; Abstand 0 pt. | Gleichung innerhalb derselben Beweiszeile umbrechen. |
| BijectiveCompositionInnerInjectiveCriterion, 8.3.4.8 | 25–26 | Theoremkopf und Delta stehen am Seitenende; die Anzeigeformel erst auf der nächsten Seite. | Kopf, Delta und Formel gemeinsam halten. |

Die Spaltenenge wurde zusätzlich mit `pdf-qa/composition-25-bbox.html` bestätigt: Begründungen beginnen bei x=388,609 pt; die Enden der drei Formelzeilen liegen bei x=388,609/387,761/388,609 pt. Es handelt sich um fehlenden optischen Abstand, nicht um über den Seitenrand abgeschnittenen Inhalt.

Keine weiteren Layoutbefunde im ersten Stand. Dieser Review änderte keine TeX-Quelle und startete keinen LaTeX-Build.

## Nachkontrolle des ersten Layout-Nachbaus

PDF-SHA256: `e6ad5a924127c622d207452ad14306dd160cacdb19a14e774a58cdf701702634`. Die Seiten 24–32 wurden erneut gerendert und visuell geprüft (`pdf-qa/composition-final-24.png` bis `composition-final-32.png`). Alle vier ursprünglichen Befunde sind behoben: Die drei Gleichungen haben gut getrennte Begründungsspalten; Kopf, Delta und Aussage von 8.3.4.8 stehen gemeinsam auf Seite 26.

Die Prüfung der Seitenfortsetzungen fand zwei durch den neuen Seitenfluss entstandene Kopftrennungen: 8.3.4.14 stand allein am Ende von Seite 29, während Delta und Formel auf Seite 30 folgten; bei 8.3.4.16 standen Kopf und Delta am Ende von Seite 30, die Formel auf Seite 31. Diese beiden konkreten Folgeeffekte wurden Root zur entsprechenden lokalen Bindung gemeldet und im zweiten Nachbau behoben. Belege des Zwischenstands: `composition-final-29.png`, `composition-final-30.png`, `composition-final-31.png`.

Die drei neuen Darstellungswrapper ändern keinen mathematischen Inhalt: `composition-layout-semantic-check.json` bestätigt für alle 242 Zeilen identische Formeln nach Entfernung ausschließlich der Umbruchwrapper sowie identische Gründe und Abhängigkeiten. Die semantischen Inventare und Hashes wurden auf den Nachbau-Quellenstand gebracht; auch die 200 selektorgeprüften Referenzen sind weiterhin fehlerfrei.

## Endkontrolle nach dem zweiten Layout-Nachbau

Finaler PDF-SHA256: `29f4d8225e24ac138f7ef8c9ab23416ded96ec762798cbfff720fe35fb03131d`. Build und Referenzaudit bestanden laut `build-layout-final.log` am 07.09.2026 um 17:39:18.

Die endgültigen physischen Seiten 29–32 wurden erneut angesehen. Die Sätze 8.3.4.14 und 8.3.4.15 stehen jeweils vollständig mit Kopf, Delta, Formel und Beweis auf Seite 30; 8.3.4.16 steht vollständig auf Seite 31. Der Übergang zu 8.3.5.1 und dessen erster Hilfsaussage ist auf Seite 31 sauber gesetzt. Alle zuvor gemeldeten Abstände und Kopfbindungen sind behoben.

Die finalen Renderings `pdf-qa/composition-final2-21.png` bis `composition-final2-28.png` sind byteidentisch mit den bereits visuell geprüften entsprechenden Seiten der vorherigen QA-Stände; Vergleichsbeleg: `pdf-qa/composition-final-render-comparison.json`. Damit sind sämtliche endgültigen Kompositionsseiten 21–31 abgedeckt. Die letzte Nachkontrolle ist in `composition-pdf-qa.json` zusammengefasst.

Alle drei semantischen JSON-Inventare, der Quellenvergleich der 242 Kompositionszeilen und die Prüfung der 200 Referenzselektoren wurden anschließend auf den endgültigen Quellenstand aktualisiert. Es verbleibt keine semantische oder visuelle Korrektur innerhalb dieses beauftragten Reviewumfangs.
