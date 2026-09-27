# Frankls Spezialfälle: Anmerkungen und Dreiermengenbeispiel

## Übernommene Anmerkungen

Die handschriftlichen Anmerkungen der angehängten Lesefassung betreffen die
gedruckten Seiten 4, 5 und 8. Die Vierfeldertafel ist jetzt schon in ihrer
Überschrift ausdrücklich dem Leitbeispiel zugeordnet. Der gestrichene Satz
mit dem zusätzlichen Tabellenverweis nach der Injektivität von
`X ↦ X ∪ {a,b}` wurde entfernt.

Beim Dreierfall erklärt eine kleine Tabelle die vier Größen `n₀,…,n₃`.
Der Text begründet, warum ein Mitglied mit genau k der drei Elemente k-mal
zur Summe der Häufigkeiten beiträgt. Die Rechnung mit `3|M|/2` enthält den
gewünschten Zwischenschritt mit `|M| = n₀+n₁+n₂+n₃`. Die Summenschranke ist
als hinreichende Bedingung formuliert.

## Das ergänzte Beispiel

Das Beispiel aus Abschnitt 4, Abbildung 1 von
[van der Hout und Roos (2026)](https://doi.org/10.23952/jano.8.2026.1.02)
besteht aus 19 Mengen auf sieben verschiedenen Elementen. Die enthaltene
Dreiermenge `A={a,b,c}` besitzt ausschließlich Elemente mit neun Vorkommen.
Die vier anderen Elemente kommen 14-, 14-, 14- und 17-mal vor.
Das Beispiel widerlegt die entsprechende Verstärkung des Zweiermengensatzes
auf ein vorgegebenes Dreiermitglied. Es widerlegt Frankls Vermutung nicht.

Die Lesefassung zeigt alle 19 Mengen in einer nach Bausteinen gegliederten
Inzidenztafel. Ein eigener kurzer Beweis erklärt den Vereinigungsabschluss
anhand dieser Bausteine. Das Beispiel enthält keine Einermengen oder
Zweiermengen; eine Behauptung, es sei kleinstmöglich, wird nicht gemacht.
Historischer Abriss und Schlussbemerkung bleiben die letzten beiden Abschnitte.

## Trennung der Aussagen und Beweise

Band 46 und der Gesamtband erhalten genau einen neuen Existenzsatz mit der
Kennung `FranklRareTripleExists` und Nummer **46.3.8.1**. Er wird nach den bisherigen Abschnitten
angefügt, damit sämtliche bestehenden Nummern und Sprungziele erhalten bleiben.
Konstruktion, Hilfssätze und Beweise gehören ausschließlich in den Beweisband.
Neue Hilfssätze erhalten den unabhängigen Nummernraum `46E`.

Die ursprünglichen 17 ausgelagerten Aussagen und Tabellen bleiben unverändert.
Das ursprüngliche Manifest wird weiter als unveränderte Referenz geprüft;
der neue Hauptsatz ist eine ausdrücklich zugelassene Ergänzung.

## Prüfungen

`scripts/frankl-triple-audit.py` liest die tatsächlich gesetzten Inzidenzzeilen
aus der LaTeX-Quelle. Es prüft die Bezeichnungen gegen die sieben Spalten,
alle 361 geordneten Vereinigungen, die sieben Häufigkeiten und die vier
Zählklassen `(5,6,3,5)`. Diese endliche Prüfung bestätigt das konkrete Beispiel.
Die beiden Inzidenztafeln und alle sechs neun- bzw. zehnstelligen Indexlisten
werden ebenfalls gegeneinander geprüft. Die formale Herleitung wurde
zusätzlich unabhängig gelesen: Basisfälle und rekursive Quellen der
Listenregeln, Projektionen und Fallentladungen, die Aussonderung der
Teilmengenfamilien, der Injektionstransport auf die natürlichen Anfangsstücke
und die sieben konkreten Existenzzeugen wurden kontrolliert.

Die Beweistabellen benutzen die Wiederholungsnotation aus Band 01.
Rekursive Kurzterme sind ausdrücklich als endliche Quellenfolgen definiert;
sie führen keine zusätzlichen Schlussregeln oder Axiome ein. Der
Vereinigungsabschluss verwendet ein kleines Schema für fünf Bausteine,
das sämtliche 361 einzelnen Instanzen bestimmt. Ein unbenutztes Hilfslemma
wurde bei der Kürzung entfernt.

Die fertige Lesefassung hat 14 Seiten, die Beweistabellen 33 Seiten.
Alle neuen Seiten wurden gerendert und visuell geprüft; die beiden
Ergänzungen haben keine übervollen Zeilen, fehlenden Satzverweise oder
nicht aufgelösten Sprungziele. Die neue Konstruktion verwendet 21 lokale
Deklarationen (zwei Definitionen und 19 Hilfssätze). Die letzte
Layoutkontrolle bestätigt insbesondere den Zusammenhalt von
Abschnittsüberschriften und Aussagen sowie den Abstand zwischen Formeln
und Begründungen.

Band 46 hat 90, der Überblick 113 und der neu erzeugte Gesamtband
2.656 PDF-Seiten. Der neue Hauptsatz steht im Gesamtband auf PDF-Seite
2.470 (gedruckte Seite 2.469); diese Seite wurde ebenfalls visuell geprüft.
Der reguläre Build-Audit für B00, B46 und den Gesamtband ist bestanden,
einschließlich des Abgleichs aller Bandregister und Satznummern mit den
Einzelbänden. Der Frankl-Audit bestätigt die unveränderten ursprünglichen
17 Aussagen sowie alle 18 direkten Verknüpfungen zu ihren Beweisen.

Lesefassung, Beweistabellen, Band 46, Überblick und Gesamtband sind unter
ihren bestehenden Namen im Ausgabeordner erneuert. Ein Vergleich der
dekodierten PDF-Seiteninhalte bestätigt, dass alle 47 veröffentlichten
Seiten der beiden Frankl-Ergänzungen mit den visuell geprüften
Build-Fassungen übereinstimmen; beim Publizieren wurden nur die externen
PDF-Ziele auf die Ausgabeordner umgeschrieben.
Die abschließende Linkprüfung des Ausgabeordners ist bestanden:
66 PDFs, 5.783 Seiten, 61.883 interne und 41.566 externe Verknüpfungen.
