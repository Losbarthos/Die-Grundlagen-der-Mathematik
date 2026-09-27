Integration der Rekonstruktion mittels Nullproduktprofilen

Quelle und Umfang

Ausgangspunkt ist die letzte ausführliche Antwort der geteilten Unterhaltung https://chatgpt.com/share/6ab6cc27-72d8-83ed-b081-c0255d3a43fe. Der bewiesene Spezialfall betrifft eine endliche Halbgruppe S mit Null und S²={0,c}, c≠0. Aus einem Isomorphismus der Potenzhalbgruppen der nichtleeren Teilmengen folgt S≅T. Die Endlichkeit und das Nullelement von T werden hergeleitet. Eine Lösung der allgemeinen endlichen Rekonstruktionsvermutung oder eine Erhaltung von Einermengen durch den gegebenen Isomorphismus wird nicht behauptet.

Einordnung

- Band 03: kleine nichtleere Potenzmengen und das Argument mit Einermengen und Gesamtträger in einer dreielementigen Mengenfamilie.
- Band 05: Bilder von Paar- und Dreiermengen.
- Band 08: Bijektionen mit zwei vorgeschriebenen Werten sowie Fortsetzung eines weiteren passenden Werts durch Transposition.
- Band 09: Verklebung beliebiger Faserbijektionen, auch bei leeren Fasern und ohne Surjektivität der Profilabbildungen.
- Band 12: Präordnungen, symmetrischer Kern und Quotientenordnung.
- Band 20: endliche Komplementkürzung, Induktion über endliche partielle Ordnungen und Rekonstruktion von Fasergrößen aus kumulativen Größen.
- Band 28: allgemeine Produktquadratdaten und Gleichheit von Potenzquadrat und Potenzmenge des Quadrats im Zweierfall.
- Band 33: Nullproduktprofile, ihre Ordnung, untere Mengen, Transport und markierte Rekonstruktion der Nullrelation.
- Band 37: kanonischer Rekonstruktionssatz mit verknüpfter Lesefassung und eigenständigen Beweistabellen.

Die Ergänzungen benötigen keinen neuen Fachband und keine neuen mathematischen Axiome. Die allgemeinen Hilfssätze stehen vor ihrer Anwendung. Die Quellen des neuen Satzes und der beiden Fassungen liegen unter `tex/b37/nullproducts/`.

Besonders geprüfte Punkte

1. Der Profilquotient ist ein geordneter Quotient, keine vorausgesetzte multiplikative Kongruenz.
2. L_p=P*(D_p) zählt genau die nichtleeren Teilmengen der unteren Grundelementmenge. Die Zählung betrifft weder bloß die Zahl der Profile noch alle Mengen einer einzelnen Äquivalenzklasse.
3. Leere Singletonfasern sind zulässig. Zwei ausgezeichnete Grundelemente dürfen demselben Profil angehören.
4. Der Zählschritt verwendet die vorhandene endliche Potenzmengenzählung, Faserverklebung und Komplementkürzung. Logarithmen und allgemeine Inversionstheorie werden nicht benötigt.
5. Aus drei Produktmengen der Potenzhalbgruppe wird ein zweielementiges Grundquadrat hergeleitet. Die Gleichheit P*(A)²=P*(A²) wird ausschließlich unter der bewiesenen Zweierquadratvoraussetzung verwendet.
6. Die Zielnull wird getrennt in den Fällen c²=0 und c²=c gewonnen. Ein Nullelement der Potenzhalbgruppe allein wird nicht als Nullelement der Grundhalbgruppe ausgegeben.
7. Im idempotenten Fall wird nur die benötigte Zweierstruktur betrachtet; eine Potenzhalbgruppe eines beliebigen Halbverbands wird nicht als idempotent vorausgesetzt.
8. Der abschließende Isomorphismus fixiert die beiden Produktwerte und erhält die Nullrelation. Erst daraus folgt die Erhaltung der gesamten Multiplikation.

Rechnerische Zusatzkontrolle

`python scripts/check-nullproducts-examples.py` prüft alle assoziativen Tafeln auf zwei, drei und vier fest beschrifteten Elementen, bei denen 0 Null ist und die Produktmenge genau {0,1} ist: 1+3+19=23 Tafeln. Geprüft werden die drei Produktmengen, die Identität L_p=P*(D_p) und die Rückgewinnung der Fasergrößen. Außerdem werden das Dreierbeispiel, der Singleton-Tausch einer Potenznullhalbgruppe und das Fünferbeispiel zur Grenze der Nullrelation geprüft. Diese endliche Kontrolle ist keine Ersetzung des allgemeinen Beweises.

Die Ergänzungen enthalten insgesamt 2.225 Beweiszeilen. Die automatische Abhängigkeitsprüfung kontrolliert bei 2.199 davon Zeilennummern und offene Annahmen ohne Fehler; die übrigen 26 ausgeschriebenen Ableitungsblöcke wurden manuell geprüft. Die gerichtete Gleichheitselimination, erforderliche Symmetrieschritte, Konjunktionsprojektionen und Äquivalenzabtrennungen wurden gesondert kontrolliert und präzisiert. Diese Prüfungen sind keine maschinelle Zertifizierung der mathematischen Aussagen; zusätzlich wurden Voraussetzungen, Beweisschritte und die Übereinstimmung der Lesefassung manuell geprüft.

Build- und Sichtprüfung

Der neue Hauptsatz trägt die Nummer 37.5.6.1. Die Lesefassung umfasst 9 PDF-Seiten, die zugehörigen Beweistabellen 35 PDF-Seiten. Der neu gebaute Gesamtband umfasst 2.736 PDF-Seiten. Die allgemeinen Hilfssätze mit ihren Beweisen sind zusätzlich in den oben genannten Grundlagenbänden enthalten; die 35-seitige Tabellenfassung verweist auf diese zuvor bewiesenen Aussagen.

Alle betroffenen Einzelbände, beide Ergänzungen und der Gesamtband wurden erfolgreich mit LuaLaTeX/latexmk gebaut. Die Referenzprüfung bestand für B00, B03, B05, B08, B09, B12, B20, B28, B33, B37 und den Gesamtband; dabei wurden auch die 49 Satzregister des Gesamtbands mit den Einzelbänden abgeglichen. Die gesonderten Editionsprüfungen bestätigten Nummerierung, eindeutige Eigentümerschaft des Hauptsatzes, Navigation und Querverweise. Die 159 vorher vorhandenen Registereinträge von Band 37 einschließlich Nummern und Zielen blieben unverändert; die 25 Hilfsaussagen der Tabellenedition besitzen einen getrennten Nummernraum.

Alle Seiten beider neuen Fassungen sowie sämtliche neuen Abschnitte der betroffenen Einzelbände wurden als gerenderte PDF-Seiten visuell geprüft. Ausgewählte entsprechende Stellen im Gesamtband wurden zusätzlich kontrolliert. Lange Formeln und Begründungen wurden passend umbrochen; Überschriften und Abschlusszeilen wurden mit ihren zugehörigen Beweisteilen zusammengehalten. Bestehende Satzspiegelwarnungen älterer Inhalte wurden nicht durch Änderungen außerhalb des Auftrags bereinigt.

Die fertigen Ausgaben liegen unter `output/`, die beiden neuen Fassungen im Unterordner `07 Halbgruppen und Monoide/Ergänzungen/Nullprodukt-Rekonstruktion/`. Der abschließende Publikationsaudit bestand für alle 70 veröffentlichten PDFs mit insgesamt 6.023 Seiten: 64.502 interne und 44.880 externe Verweise waren gültig. Das Protokoll liegt unter `tmp/nullproducts-qa/final-publication.txt`.

Nach der mathematischen, formalen und redaktionellen Prüfung sind keine offenen Beweislücken bekannt. Vorhandene Inhalte und zuvor bestehende lokale Änderungen wurden erhalten.
