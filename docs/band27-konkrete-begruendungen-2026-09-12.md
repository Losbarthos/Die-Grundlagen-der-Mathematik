# Band 27: konkrete Quellen der Beweisschritte

Die Überarbeitung ersetzt unspezifische Tabellenbegründungen wie „Elementkriterium“, „Bildkriterium“, „Typisierung“ oder „Abkürzung“ durch Verweise auf tatsächlich verfügbare Definitionen, Axiome und Sätze sowie durch die zugehörigen Schlussregeln. Die Eingangserhebung erfasste 168 solcher Begründungen. Ein bloßer Austausch der Bezeichnung genügte vielfach nicht: Die fehlenden Ableitungsschritte wurden ergänzt.

Die zuvor eingeführte Gliederung bleibt bestehen: Zunächst werden die konkreten Wort- und Baumkonstruktionen begründet. Unmittelbar anschließend werden ihre Struktureigenschaften als Axiome formuliert. Induktion, Zerlegung, Rekursion und Isomorphiesätze werden danach aus diesen Axiomen hergeleitet.

## Inhaltliche Änderungen

- Wiederkehrende Mengenargumente haben zitierbare Hilfssätze erhalten: termgebildete Mengen, Funktionsfasern und die Anfügung eines geordneten Paares. Die Voraussetzungen jedes Hilfssatzes werden in den Anwendungen nachgewiesen.
- Die abstrakten Rekursionsbeweise für Wörter und Bäume führen die abgeschlossenen Graphen und ihre Faserfilter ausdrücklich ein. Existenz, Funktionseigenschaft, Rekursionsgleichungen und Eindeutigkeit werden getrennt hergeleitet.
- In den Induktions-, Zerlegungs- und Isomorphiebeweisen sind die nötigen Typannahmen, Quantoreinführungen, Zeugeneliminationen und Gleichheitsersetzungen sichtbar gemacht.
- Die Verbindung mit gerichteten und ungerichteten Wurzelbäumen stützt sich auf gesonderte Sätze über Elternsysteme, Höhenzunahme, Erreichbarkeit und Eindeutigkeit der Wurzelwege. Präfixabschluss und volle Verzweigung der zusammengesetzten Adressmengen werden ebenfalls durch eigene Hilfssätze begründet.
- Die bereits vorhandenen Definitionen „Iota-Symbol“ und „Iota-Definition“ in Band 1 haben beständige Registerkennungen erhalten. Ihr mathematischer Inhalt und ihre Nummern bleiben unverändert; es werden keine zusätzlichen logischen Axiome vorausgesetzt.
- Die global quantifizierten Klauseln der konkreten Rekursionssätze sind ausdrücklich geklammert.

„Elementkriterium“ darf weiterhin Bestandteil eines Satznamens sein. Als Begründung dient dann dessen konkreter nummerierter Verweis mit den erforderlichen Voraussetzungen.

## Prüfung

Die geänderten Beweise wurden unabhängig gegengelesen, insbesondere hinsichtlich der Voraussetzungen bei leeren Wörtern, der Richtung von Gleichheitsersetzungen und der Gültigkeitsbereiche gebundener Variablen. Die technischen Prüfungen ergänzen diese mathematische Durchsicht; sie sind keine maschinelle Verifikation sämtlicher Beweise.

- Die Quellenprüfung erfasst 42 tatsächlich eingebundene Dateien, 456 benannte Deklarationen und 1530 benannte Verweise. Sie findet keine fehlenden oder doppelten Deklarationen und keine Verweise auf später eingeführte Ergebnisse. In den Beweistabellen bleiben keine der erfassten pauschalen Begründungen zurück.
- Band 1 und Band 27 bestehen die Build- und Verweisprüfung. Die fertige Einzelbandfassung von Band 27 umfasst 251 Seiten; ihre 4702 externen PDF-Verknüpfungen führen zu 247 verschiedenen Zielen.
- Die betroffenen Bände 28 bis 46, Band 48 und der Überblick wurden mit den aktualisierten Satzverweisen neu erstellt und einzeln geprüft.
- Gerenderte Seiten der geänderten Wort- und Baumbeweise wurden visuell kontrolliert. Lange Formeln wurden von der Begründungsspalte getrennt; Satz- und Teilbeweisköpfe werden an den korrigierten Übergängen mit ihren Formeln zusammengehalten. Zusätzliche Sichtproben betreffen den Überblick zu Band 27 und die Formelcode-Brücke in Band 48.
- Die aktualisierten Einzelbände wurden nach `output` übernommen. Die abschließende Linkprüfung aller 49 Einzelband-PDFs besteht: 2841 Seiten, 13767 interne und 38663 externe Verknüpfungen.
- Die Gesamtfassung wurde mit 2812 Seiten neu erstellt. Der Abgleich mit allen 49 Einzelband-Registern besteht; die Gesamt-PDF enthält keine externen PDF-Verknüpfungen. Acht gerenderte Stichprobenseiten zu den neuen Hilfssätzen, beiden Axiomensystemen, beiden Rekursionen, der Knotenregel und den Wurzelwegen wurden ohne Befund geprüft.
- Nach erfolgreicher Prüfung ihrer 52480 internen Sprungziele wurde auch die Gesamt-PDF nach `output` übernommen.

Die aktuellen Prüfnachweise liegen unter `tmp/b27-explicit-references/`. Maßgeblich sind `final-source-audit.json`, `audit-b27-final.log`, `audit-main-final.log` und die beiden Veröffentlichungsprotokolle `publish-standalone.log` und `publish-main.log`. Die ursprüngliche Erhebung und die Zwischenstände der Prüfläufe sind dort ebenfalls dokumentiert.
