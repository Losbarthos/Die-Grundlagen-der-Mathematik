# Band 27: Induktionsaxiom und Vergleich mit Peano

Stand: 15. September 2026. Ergänzung zur Rekursionsüberarbeitung vom 14. September.

## Ergebnis der mathematischen Prüfung

Das Induktionsprinzip fehlte nicht: W3 enthielt es bereits unter dem Namen „Minimalität“. Enthält eine Teilmenge des Wortträgers das Anfangswort und ist sie unter sämtlichen Buchstabenanfügungen abgeschlossen, so ist sie der ganze Träger. Das ist die Mengenform der strukturellen Induktion.

Die Überarbeitung macht dieses Prinzip wie in der aktiven Peano-Schnittstelle von Band 10 ausdrücklich als Axiom und unmittelbar anwendbare Beweisregel sichtbar. Die Klasse der zugelassenen Wortstrukturen ändert sich dadurch nicht.

## Vergleich der Schnittstellen

| Peano-Schnittstelle in Band 10 | Wortstruktur in Band 27 |
| --- | --- |
| Null gehört zum Träger. | W0 enthält das Anfangswort im Träger. |
| Der Nachfolger ist eine totale Funktion auf dem Träger. | W0 verlangt eine totale Anfügungsfunktion auf Wort-Buchstaben-Paaren. |
| Universeller und sequenzieller Nachfolgerabschluss. | Folgen unmittelbar aus W0; der entsprechende Hilfssatz bleibt erhalten. |
| Kein Nachfolger ist Null. | W1 schließt das Anfangswort aus allen Nachfolgerbildern aus. |
| Der Nachfolger ist injektiv. | W2 ist auf ganzen Paaren injektiv: Vorgängerwort und letzter Buchstabe sind eindeutig. |
| Induktionsaxiom und Induktionsregel. | W3 steht in Mengenform, Prädikatsform und Regelform unmittelbar bei den Strukturaxiomen. |
| Jede Nichtnullzahl ist Nachfolger. | Die Endzerlegung folgt aus W3; ihre Eindeutigkeit aus W2. |

Kein weiteres unabhängiges Axiom fehlt. Insbesondere wäre ein zusätzliches Axiom für Vorgängerexistenz redundant. Nichtleerheit des Wortträgers folgt bereits aus W0. Das Alphabet darf leer sein; dann folgt aus W3, dass der Träger nur aus dem Anfangswort besteht. Bei einem einzigen Buchstaben entsteht die Peano-Struktur, bei mehreren Buchstaben ihre verzweigte Verallgemeinerung.

Die Injektivität jeder einzelnen Buchstabennachfolgerfunktion allein wäre zu schwach: Verschiedene Buchstaben könnten dann dieselbe Fortsetzung liefern. Die bereits vorhandene gemeinsame Injektivität in W2 schließt dies aus.

## Änderungen an Darstellung und Beweisen

- W3 trägt ausdrücklich die Bezeichnung „Induktionsaxiom in Mengenform“; „Minimalität“ bleibt als gleichbedeutende Beschreibung erläutert.
- `WordStructureInduction` und `WordStructureInductionRule` sind direkt bei den Axiomen als gleichwertige Prädikats- und Regelform registriert. Sie sind keine zusätzlichen unabhängigen Voraussetzungen.
- Die bisherigen Herleitungen bleiben als Begründungen dieser Formen erhalten, ohne dieselben Aussagen ein zweites Mal als Theoreme zu registrieren. Die Prädikatsform wird ausschließlich aus W0 und der Mengenform von W3 gerechtfertigt. Die Regelform folgt durch Einführung und Beseitigung der Quantoren und Implikationen.
- Die Rückübersetzung zur Mengenform verwendet das Prädikat „das Wort gehört zu U“. Mengenparameter sind ausdrücklich zugelassen; die Mengenform umfasst jede Teilmenge des Trägers.
- Die Eigenvariablenbedingungen der Regel und das zulässige Weglassen einer nicht benötigten Induktionsannahme sind erklärt.
- Endzerlegung, Rekursionseindeutigkeit, Vollständigkeit der Rekursionsstufen und die weiteren Wortinduktionsbeweise verweisen unmittelbar auf die axiomatische Form. Zahleninduktion über die Stufennummern bleibt Peano-Induktion.
- Vier gerichtete Gleichheitssubstitutionen in den Folgebeweisen sind formal korrigiert: in der Übertragung der Induktion auf Konkatenation (Zeile 8), im Abschlussbeweis für die Wortmenge (Zeile 9) sowie im Assoziativitätsbeweis (Zeilen 5 und 14). Die Gleichheitsregel aus Band 01 verlangt dort jeweils die zuvor symmetrisierte Gleichung.
- Bei der konkreten Strukturinduktion werden Überschrift, Parameter und Formel als gemeinsamer Block gesetzt, sodass die Aussage nicht über einen Seitenwechsel zerfällt.
- Die Einleitung, der konkrete Nachweis von W3, die Folgeabschnitte und der Überblick sind sprachlich angeglichen. Der Vergleich mit Band 10 steht direkt bei den Wortaxiomen.

## Prüfung

Zwei unabhängige mathematische Prüfungen bestätigen die vollständige Peano-Zuordnung und die zirkelfreie Begründung der Induktionsformen. Eine zusätzliche statische Quellenprüfung erfasst 613 Beweiszeilen in 39 Beweisblöcken der betroffenen Axiom-, Modell- und Folgequellen: keine unbekannten Regelmakros, fehlerhaften Klammerungen, Vorwärtsverweise auf Beweiszeilen oder Verweise auf Nichtannahmen in den Abhängigkeitslisten. Dies ist eine Quellenprüfung, keine Zertifizierung durch einen Beweisassistenten.

Band 27, die abhängigen Bände 28–48, der Überblick und der Gesamtband wurden neu gesetzt. Die übrigen Einzelbände wurden aus ihrem bereits geprüften Buildstand erneut bereitgestellt. Der vollständige Buildaudit bestätigt für alle 49 Einzelbände und den Gesamtband aufgelöste Verweise; Ergebnisregister und Satznummern stimmen zwischen Einzel- und Gesamtausgabe überein.

Die abschließende Prüfung des Ausgabeordners ist bestanden: **50 PDFs, 5.708 Seiten, 66.375 interne Links und 38.631 bandübergreifende Links**. Band 27 umfasst 246 PDF-Seiten, der Gesamtband 2.840. Die Wortaxiome und der Peano-Vergleich stehen in Band 27 auf den gedruckten Seiten 38–41, im Gesamtband auf den gedruckten Seiten 1709–1712.

Visuell anhand gerenderter Seiten geprüft wurden:

- Band 27: PDF-Seiten 35–74, 78–80, 91–94, 104–107 und 242–246. Die vier korrigierten Substitutionen und der zusammengehaltene Induktionssatz wurden nach der letzten Änderung erneut kontrolliert.
- Überblick: PDF-Seiten 65–72.
- Gesamtband: PDF-Seiten 98–105, 1707–1721, 1743, 1764 und 1775–1778.
- Abschließende Stichprobe der tatsächlichen Ausgabedateien: Band 27, PDF-Seite 41; Gesamtband, PDF-Seiten 1712 und 1776.

In den abschließend kontrollierten Bereichen sind keine abgeschnittenen Formeln, Überlagerungen oder fehlerhaften Trennungen der Induktionsaussagen verblieben. Die Prüfprotokolle und Renderings liegen unter `tmp/b27-stufen-qa/induction-*`; insbesondere dokumentieren `induction-audit.console.log` und `induction-publish-final.console.log` die erfolgreichen vollständigen Verweisprüfungen.
