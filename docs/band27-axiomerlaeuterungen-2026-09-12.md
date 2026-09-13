# Band 27: Bedeutung und Herkunft der Strukturaxiome

Die Abschnitte über Wort- und Baumstrukturen erläutern jetzt ihre Symbole vor der jeweiligen Strukturdefinition. Jedes der neun Einzelaxiome erhält außerdem einen unmittelbar anschließenden Kommentar mit seiner Bedeutung und dem konkreten zuvor bewiesenen Herkunftssatz.

Bei Wörtern werden insbesondere das Alphabet `A`, der Wortträger `W`, das Anfangswort `e`, die Anfügungsfunktion `s` und die Teilmenge `U` erklärt. Beispiele zeigen das Anfügen eines und zweier Buchstaben. Die konkrete Belegung durch das Vorkommensmodell wird von beliebigen abstrakten Strukturdaten unterschieden; insbesondere muss das abstrakte Anfangswort nicht die leere Menge sein.

Bei Bäumen werden `T` als Menge ganzer Bäume sowie Blatt- und Knotenkonstruktor erklärt. Die beiden Argumente des Knotenkonstruktors sind ganze Teilbäume mit festgelegter linker und rechter Rolle. Auch das Produkt `T × T`, die beliebige Teilmenge `U` und das Bild des Blattkonstruktors werden erläutert.

Die Herkunftszuordnung im konkreten Modell lautet:

| Axiom | Zuvor bewiesenes Theorem | Beständige Kennung |
| --- | --- | --- |
| W0 | 27.2.3.3 | `EarlyWordSuccessorTyping` |
| W1 | 27.2.3.6 | `EarlyWordSuccessorNonempty` |
| W2 | 27.2.3.8 | `EarlyWordSuccessorInjective` |
| W3 | 27.2.3.13 | `EarlyWordModelMinimality` |
| B0 | 27.3.3.2 | `TreeCodeConstructorTyping` |
| B1 | 27.3.3.5 | `TreeCodeLeafInjectivity` |
| B2 | 27.3.3.6 | `TreeCodeNodeInjectivity` |
| B3 | 27.3.3.7 | `TreeCodeConstructorSeparation` |
| B4 | 27.3.3.9 | `TreeCodeMinimality` |

Die Herkunftssätze beweisen diese Eigenschaften für die zuvor konstruierten Modelle. Für beliebige Strukturdaten werden sie als Bedingungen gefordert. Die nummerierten Axiome entnehmen unter der jeweiligen Strukturannahme eine Bedingung der Strukturdefinition. Diese Unterscheidung wird im Band ausdrücklich erklärt.

Formale Aussagen, Beweise und Registereinträge wurden nicht verändert. Das nach dem Neubau erzeugte Band-27-Register ist mit dem vor der Ergänzung gesicherten Register bytegleich. Die Prüfung der Einfügereihenfolge findet bei 456 benannten Deklarationen und 1541 benannten Verweisen keine fehlenden, doppelten oder vorwärts gerichteten Verweise.

Die Einzelbandfassung umfasst 253 Seiten und besteht die Verweisprüfung. Die neuen Worterläuterungen wurden auf den physischen PDF-Seiten 36–39, die Baumerläuterungen auf den Seiten 127–131 visuell geprüft. Axiome und zugehörige Kommentare bleiben zusammen; die anschließenden Modellbeweise und Folgerungen sind sauber gesetzt.

Die aktualisierte Band-27-PDF wurde nach `output` übernommen. Die anschließende Verknüpfungsprüfung sämtlicher 49 Einzelbände besteht: 2843 Seiten, 13778 interne und 38663 externe Verknüpfungen. Wegen des unveränderten Registers war kein Neubau der Folgebände erforderlich.

Auch der Gesamtband wurde neu gebaut und nach bestandener Quellen- und Verweisprüfung nach `output` übernommen. Er umfasst 2814 Seiten; sämtliche 52491 internen PDF-Verknüpfungen bestehen die Zielprüfung, externe PDF-Verknüpfungen enthält er nicht. Die sechs betroffenen Seiten mit Symbolübersichten und Axiomkommentaren (physische Seiten 1675–1677 und 1766–1768) wurden zusätzlich in der Gesamtfassung visuell geprüft.

Die Prüfprotokolle und gerenderten Seiten liegen unter `tmp/b27-axiom-explanations/`.
