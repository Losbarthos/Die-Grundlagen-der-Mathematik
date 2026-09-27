# Gruppenrekonstruktion: Anmerkungen und Zusammenhang mit der Potenzhalbgruppenvermutung

Stand: 25. September 2026. Grundlage ist die vom Benutzer bereitgestellte, auf dem reMarkable annotierte Fassung `Band 40 - Gruppenrekonstruktion - Lesefassung.pdf` mit 13 PDF-Seiten. Alle Seiten wurden visuell gesichtet; die inhaltlichen Randfragen stehen auf den gedruckten Seiten 1 bis 5. Der Export enthält die Handschrift als Seiteninhalt, nicht als auslesbare PDF-Kommentare.

## Eingearbeitete Anmerkungen

1. **Warum beantworten die Sätze die Eingangsfrage?** Die Einleitung erklärt Rekonstruktion als Bestimmung bis auf Isomorphie. Die Einheiten der Potenzhalbgruppe liefern eine konkrete isomorphe Kopie der Ausgangsgruppe, nicht deren ursprüngliche Elementnamen.
2. **Wie sieht das Vorgehen konkret aus?** Das Zweiergruppenbeispiel enthält nun das Verfahren: neutrales Element bestimmen, die beidseitig invertierbaren Eingaben auswählen und die Multiplikation auf diese Eingaben einschränken. Die verbleibende Zweiertafel und die produktverträgliche Bijektion werden ausgeschrieben. Für unendliche Gruppen wird kein endliches Suchverfahren behauptet.
3. **Allgemeine Mengengleichheit anstelle wiederholter Zeugenargumentation.** Die Lesefassung verweist auf den vorhandenen Satz `B27TermImagePointwiseEquality` und zwei ergänzte, formal bewiesene Schemata in Band 3. Die drei zugehörigen Beweisteile der Potenzhalbgruppenassoziativität in Band 28 verwenden jetzt das allgemeine Dreifachzeugenschema. Ihre bisherigen Kennungen, Voraussetzungen und Gliederung bleiben erhalten; die Tabellen haben 12, 12 und 10 statt 13, 14 und 11 Zeilen.
4. **Umkehrabbildung und Erhaltung der algebraischen Struktur.** Der vorhandene Satz `SemigroupIsoInverse` (28.2.15.1) wird ausdrücklich verwendet. Neue Tabellen ergänzen die entsprechenden Umkehrsätze für Monoide und Gruppen sowie den Gruppentransport entlang eines Halbgruppenisomorphismus. Die Lesefassung unterscheidet einen bereits vorliegenden Isomorphismus der Grundstrukturen von einem erst gegebenen Isomorphismus ihrer Potenzhalbgruppen.
5. **Neutralität von E ausdrücklich zeigen.** Für ein beliebiges nichtleeres Z wird mittels Surjektivität ein X mit F(X)=Z gewählt. Beide Rechnungen EZ=Z und ZE=Z sind ausgeschrieben, bevor aus E ein neutrales Element der Zielhalbgruppe gewonnen wird.

## Neue Erklärung zur Vermutung

Der Abschnitt „Welche Bijektion verlangt die Potenzhalbgruppenvermutung?“ steht vor dem historischen Abriss. Er behandelt die endliche Vermutung aus Band 37 und unterscheidet:

- die Existenz irgendeines Isomorphismus zwischen den Grundhalbgruppen;
- die zusätzliche Eigenschaft eines vorgegebenen Potenzisomorphismus, Einermengen zu erhalten;
- die noch stärkere Gleichung F(X)=φ[X] auf sämtlichen nichtleeren Teilmengen.

Gesucht ist eine Bijektion, die die Multiplikation erhält. Eine bloße Bijektion der endlichen Grundmengen folgt schon aus der Anzahl ihrer nichtleeren Teilmengen und reicht nicht aus. Der Nachweis der Einermengentreue ist ein hinreichender Beweisweg, aber keine Forderung der allgemeinen Vermutung an jeden Potenzisomorphismus.

Das Gegenbeispiel zur Einermengentreue ist vollständig angegeben: Auf S={0,a} sei jedes Produkt gleich 0. Die Potenzhalbgruppe hat drei Elemente und jedes ihrer Produkte ist {0}. Die Abbildung, die {0} festhält und {a} mit S vertauscht, ist deshalb ein Automorphismus, obwohl sie die Einermengen nicht erhält. Dennoch ist die Grundhalbgruppe durch ihre Identität zu sich selbst isomorph. Das ist ausdrücklich kein Gegenbeispiel zur Potenzhalbgruppenvermutung.

Im Gruppenfall sind die Einermengen dagegen gerade die Einheiten und werden daher von jedem Potenzisomorphismus erhalten. Dies bestimmt den zu diesem Potenzisomorphismus gehörenden Grundisomorphismus auf den Einermengen. Andere Beweiswege sind möglich; die Vermutung verlangt keine vorgeschriebene Konstruktion. Ein Gegenbeispiel müsste isomorphe Potenzhalbgruppen mit tatsächlich nichtisomorphen Grundhalbgruppen verbinden.

Der historische Abriss und die Schlussbemerkung bleiben die beiden letzten Abschnitte. Die Schlussbemerkung greift die Unterscheidung zwischen Beweisweg und Existenzforderung nochmals auf. Als Primärquelle für die Einordnung des endlichen Problems dient die Einleitung von Liu–Tringali, [Power Semigroups and Two Rigidity Theorems for Groups](https://arxiv.org/html/2606.01917v1), insbesondere Questions 1.1.

## Ergänzte formale Ergebnisse

| Band | Nummer | Kennung |
| --- | --- | --- |
| 3 | 3.18.4.1 | `TripleTermWitnessPointwiseEquality` |
| 3 | 3.18.4.2 | `TripleTermRepresentationEquality` |
| 38 | 38.4.1.1 | `MonoidIsoInverse` |
| 40 | 40.4.1.1 | `GroupIsoInverse` |
| 40 | 40.4.1.2 | `SemigroupIsoGroupTransport` |

Die Ergänzungen stehen jeweils am Ende der Fachbände. Der Vergleich mit dem vor dieser Bearbeitung gesicherten Bestand bestätigt: Sämtliche bisherigen Registereinträge, Satznummern und PDF-Zielnamen in B03, B28, B38 und B40 bleiben erhalten. Das Rekonstruktionsmanifest hält den ursprünglichen Bestand unverändert fest und dokumentiert die beiden neuen Ergebnisse in B40 separat.

Die unabhängige mathematische Gegenprüfung umfasst die neue Prosa, das Nullhalbgruppenbeispiel und sämtliche neuen oder geänderten formalen Tabellen. Sie fand keine konkreten Fehler; insbesondere wurden Quantorenbedingungen, die Entlassung von Existenzzeugen, Ersetzungsrichtungen und die Voraussetzungen beim Gruppentransport geprüft. Es gibt keinen Kreisverweis zu den Rekonstruktionssätzen. Diese Prüfung ist keine maschinelle Zertifizierung der Schlussregeln.

## Technische Prüfung

Die allgemeine Quellinventur erfasst nun auch die physischen `tex/b03-*.tex`-Dateien. Die ursprünglichen zwölf ausgelagerten Rekonstruktionsaussagen und Tabellenkörper sowie die sieben in Band 40 belassenen Grundlagenbeweise sind unverändert.

Die Lesefassung umfasst jetzt **16 PDF-Seiten**. Alle Seiten wurden gerendert und visuell geprüft; das Satzprotokoll enthält keine Überläufe, fehlenden Zeichen oder undefinierten Verweise. Die Beweistabellen-Ergänzung hat weiterhin **20 Seiten**; sämtliche Seiteninhaltsströme sind identisch mit der zuvor geprüften veröffentlichten Ausgabe. Die neuen Beweise in Band 3 wurden auf den PDF-Seiten 152 bis 154 vollständig visuell geprüft.

Die Quellenprüfung meldet keine ungültigen Steuerzeichen. Das Editionsaudit bestätigt die unveränderten zwölf ursprünglichen Aussagen und Beweise, die kanonischen Verweise, die direkten Beweislinks und die leeren lokalen Ergebnisregister beider Ergänzungen.

Die betroffenen Tabellen in B28 (PDF-Seiten 13 bis 17), der neue Umkehrsatz in B38 (PDF-Seite 41) und beide neuen Ergebnisse in B40 (PDF-Seiten 28 bis 29) sind ebenfalls visuell geprüft. Drei lokale Platzvorbehalte halten Überschriften und den kurzen Schlussblock in B28 zusammen; ein lokal verringerter Tabellenvorabstand vermeidet die einzelne Schlusszeile auf der Folgeseite in B40. Die bestehenden Warnungen außerhalb der bearbeiteten Abschnitte wurden nicht als neue Fehler gewertet. Die Referenzaudits für B03, B28, B38 und B40 bestehen.

Die Einzelbände und beide Rekonstruktionsausgaben sind im Ausgabeordner aktualisiert. Die veröffentlichte Lesefassung wurde vollständig erneut gerendert: Alle 16 Seitenbilder sind pixelgleich mit dem visuell geprüften Satz. Beide Ergänzungen besitzen dieselben Seiteninhaltsströme wie ihre endgültigen Build-PDFs. Die Pfadumschreibung betrifft ausschließlich die Verknüpfungen.

Der Gesamtband wurde neu gebaut und umfasst **2.650 PDF-Seiten**. Sein Referenzaudit besteht und gleicht die Ergebnisregister und Satznummern sämtlicher Fachbände mit den Einzelausgaben ab. Die neuen beziehungsweise geänderten Abschnitte wurden auch dort visuell geprüft: PDF-Seiten 456 bis 458, 1812 bis 1816, 2193 sowie 2251 bis 2253. Die Seiten 2253 und 1816 beziehen den unmittelbaren Anschluss mit ein. Es wurden keine neuen Layoutfehler festgestellt.

Die abschließende Linkprüfung des vollständigen Ausgabeordners besteht für **68 PDFs mit 5.806 Seiten, 61.558 internen und 41.843 dateiübergreifenden Verweisen**. Alle sieben betroffenen Ausgaben (vier Fachbände, beide Rekonstruktionsausgaben und der Gesamtband) sind aktualisiert.

Auch die zwölf kontrollierten Gesamtbandseiten wurden nach der Veröffentlichung erneut gerendert und sind pixelgleich mit dem geprüften Satz.

## Nachtrag: weitere Randbemerkungen auf Seite 7

Die später angehängte Datei `1-Bd_-40-Gruppenrekonstruktion-Lesefassung.pdf` enthält ausschließlich die gedruckte Seite 7. Die beiden handschriftlichen Hinweise wurden visuell gelesen und unabhängig gegengeprüft:

- **„Menge Einheiten ist Gr.“** Die Lesefassung benennt nun ausdrücklich die Einheitengruppe: Die Einheitenmenge U bildet mit der aus A übernommenen Multiplikation eine Gruppe, entsprechend V mit der Multiplikation von B. Auch der Verweis auf 40.3.3.9 nennt diese Aussage ausdrücklich.
- **„Was ist stabil? = einheitenstabil“** Im betroffenen Argument und seiner Zwischenüberschrift wird durchgehend „einheitenstabil“ verwendet. Das vorhandene Beispiel mit den ganzen Zahlen und der Menge {-2, 2} steht jetzt unmittelbar bei der Definition. Es erläutert, dass die Menge als Ganzes unverändert bleibt, während ihre Elemente vertauscht werden dürfen; die Menge muss weder aus Einheiten bestehen noch selbst eine Gruppe bilden.

Die Änderung betrifft die Prosa der Lesefassung. Zusätzliche Beweistabellen sind nicht erforderlich; die zwölf vorhandenen Tabellen und ihre Aussagen bleiben unverändert. Historischer Abriss und Schlussbemerkung sind gegenüber der vorherigen Fassung textgleich erhalten.

Die Lesefassung hat weiterhin 16 PDF-Seiten. Editionsaudit, mathematische Gegenprüfung und visuelle Kontrolle sind abgeschlossen. Es gibt keine neuen Überläufe, fehlenden Zeichen oder undefinierten Verweise. Die endgültige Ausgabe im output-Ordner wurde erneut vollständig gerendert; alle 16 Seitenbilder stimmen exakt mit der geprüften Build-Fassung überein.
