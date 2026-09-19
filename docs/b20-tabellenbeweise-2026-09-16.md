# Tabellenbeweise zur nichtleeren Potenzmenge

Die bisherigen Fließtextbeweise von 20.3.8.19 und 20.3.8.20 sind in die
vorhandenen breiten Beweistabellen von Band 20 überführt worden. Aussagen,
Resultatnummern und Theorem-IDs bleiben unverändert. Der bereits tabellarische
Beweis von 20.3.8.21 bleibt vollständig unverändert.

| Theorem | Tabellenfassung | Herleitung |
|---|---|---|
| 20.3.8.19, Kardinalität der nichtleeren Potenzmenge | 33 Schritte in `tabproofwide` | Zerlegung der Potenzmenge, frische Adjunktion der leeren Menge, Eindeutigkeit der endlichen Kardinalzahl, Vorgängerbildung |
| 20.3.8.20, Die nichtleere Potenzmenge reflektiert endliche Kardinalität | 24 fortlaufende Schritte in drei Abschnitten von `tabproofsplitwide` | Gleichheit der Kardinalzahlen der nichtleeren Potenzmengen, Gleichheit der Zweierpotenzen, Injektivität der Zweierpotenzfunktion |

Jede Zeile weist ihre offenen Annahmen und die verwendete Schlussregel oder
den registrierten Satz aus. Die Kardinalzahlterme sind ausgeschrieben; die
Hilfsabkürzungen des Fließtexts entfallen. Alle benötigten Natürlichkeits- und
Endlichkeitsvoraussetzungen werden vor ihrer Verwendung hergeleitet.

In 20.3.8.19 wird die Nichtnullheit von `2^n` ausdrücklich bewiesen, bevor
die nur für positive natürliche Zahlen eingeführte Minus-eins-Schreibweise
verwendet wird. Die Gleichheitssubstitutionen in den Schritten 17 und 18
enthalten die notwendige Symmetrie. Der Beweis gilt auch für die leere Menge.

In 20.3.8.20 werden die beschränkten Allquantoren der Zweierpotenzdefinition
mit den nachgewiesenen natürlichen Argumenten instanziiert. Der letzte Schritt
wendet das Injektivitätsaxiom mit allen vier Voraussetzungen an.

## Prüfung

- Beide Beweise wurden unabhängig zeilenweise auf Instantiierungen,
  Annahmeabhängigkeiten, Gleichheitsrichtungen und Zeilenzitate geprüft.
- Der Neuaufbau von Band 20 und seine Verweisprüfung sind bestanden.
- Das Resultatregister von Band 20 ist bytegleich zur vorherigen Fassung.
- Der Quellvergleich bestätigt, dass nur die beiden angefragten Theoremblöcke
  geändert wurden. Die vorausgegangenen Mengenungleichheitskorrekturen bleiben
  erhalten.
- Die betroffenen Seiten des Einzelbands wurden gerendert und visuell geprüft.
  Zwei lokale Umbruchschutzstellen halten die Überschrift von 20.3.8.19 mit
  ihrer Aussage und den dritten Teilabschnitt von 20.3.8.20 mit seiner Tabelle
  zusammen. Die abschließende Sichtprüfung und die erneute Verweisprüfung
  sind bestanden; es gibt keine offenen Layoutbefunde an diesen Beweisen.

- Der Gesamtband wurde nach zwei LaTeX-Durchläufen mit 2.841 Seiten erfolgreich
  gebaut. Seine Verweisprüfung ist bestanden; die Resultatnummern stimmen mit
  den Einzelbänden überein. Band 20 umfasst 123 Seiten.
- Im Gesamtband wurden die physischen PDF-Seiten 1427 bis 1430 gerendert und
  visuell geprüft. Beide neuen Tabellen sowie der unveränderte Folgebeweis
  sind vollständig lesbar; die Überschriften und Schlussblöcke stehen sauber.
- Die Häufigkeiten und Breiten der bestehenden Overfull-Meldungen haben sich
  weder im Einzelband noch im Gesamtband erhöht.

## Bestehende PDF-Sprungziele

Die sechs entfernten manuellen Gleichungsmarken hatten den gemeinsamen
Hyperref-Linkzähler erhöht. Ohne Kompatibilitätsanker hätten sich deshalb die
späteren anonymen Satzanker der Einzelausgabe verschoben, während die anderen
veröffentlichten Bände weiterhin die bisherigen Namen verwenden.

Die Tabellen erhalten an den entsprechenden Formeln die alten unsichtbaren
Anker `AMS.164` bis `AMS.167` sowie `AMS.169` und `AMS.170`. Diese Ergänzungen
sind ausschließlich im Subfiles-/Einzelbandmodus aktiv; im Gesamtband
expandieren sie leer. Der bereits geprüfte Gesamtband bleibt dadurch
unverändert. Die Mechanik wurde unabhängig anhand der Hyperref- und
Tabellenimplementierung geprüft.

Nach dem erneuten Einzelbandaufbau sind sämtliche 872 vorherigen benannten
PDF-Ziele weiterhin vorhanden. Die dekodierten Seiteninhalte aller 123 Seiten
sind vor und nach dieser Ankerkorrektur identisch. Auch die erneute technische
Verweisprüfung von Band 20 ist bestanden.

## Aktualisierte Ausgaben

`output/02 Mengenlehre und Mengenfamilien/Bd. 20 - Endliche Mengen.pdf` und
`output/00 Einstieg und Gesamtband/Die Grundlagen der Mathematik - Gesamtband.pdf` sind aktualisiert.
Seitenzahlen, Seitengeometrien und dekodierte Seiteninhalte stimmen vollständig
mit den geprüften Build-Dateien überein.

Die abschließenden Linkprüfungen sind bestanden: alle 49 Einzelbände und der
Gesamtband, zusammen 50 PDFs mit 5.710 Seiten, 66.428 lokalen Links und 38.678
externen Links. Das Resultatregister von Band 20 ist weiterhin unverändert.
`git diff --check` meldet keine Änderungsfehler.
