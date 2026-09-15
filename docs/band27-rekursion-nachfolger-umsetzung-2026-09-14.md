# Band 27: Umsetzung der Rekursion über Auswertungsstufen

Umsetzung des [geprüften Konzepts](band27-rekursion-nachfolger-konzept-2026-09-14.md)
auf ausdrücklichen Wunsch vom 14. September 2026.

## Einstieg in die überarbeitete Fassung

Die gedruckten Seitenangaben beziehen sich auf den Einzelband 27
(die PDF-Seitenzahl liegt wegen der Titelseite jeweils um eins höher).

- Abschnitt 2.6.2, Seite 46: Übersetzungstabelle, die Abbildung `j_a`
  und die gesuchten Rekursionsgleichungen; anschließend Eindeutigkeit
  durch Wortinduktion.
- Abschnitt 2.6.3, Seite 49: Aufbau der Stufen mit dem Rekursionssatz
  für natürliche Zahlen. Die Zwischenüberschriften trennen
  Schrittfunktion, Stufenfolge, Wachstum, Eindeutigkeit der Werte,
  Totalität und Rekursionsgleichungen.
- Abschnitt 2.6.4, Seite 72: kanonische Darstellung als Übersetzung
  zwischen Wortstrukturen.
- Abschnitt 2.8.3, Seite 104: Anfang bei Buchstabenwörtern, entsprechend
  einem Anfang bei 1; Abschnitt 2.9, Seite 111: Linksfaltung.
- Abschnitt 3.4.2, Seite 145: Übergang zur Baumrekursion mit zwei
  Teilbaumwerten und Erklärung ihres Schnittbeweises.

## Inhaltliche Änderungen

- Die Wortaxiome werden den Peano-Eigenschaften gegenübergestellt:
  Anfang, je ein Nachfolger pro Buchstabe, getrennte Nachfolgerbilder
  und Minimalität. Die Erläuterungen begründen insbesondere, weshalb
  Injektivität bei nur einem festgehaltenen Buchstaben nicht ausreicht.
- Abschnitt 2.6.2 beginnt mit einer Übersetzungstabelle der
  Rekursionsgleichungen. Die konkrete Abbildung
  `j_a : N -> W`, mit Anfang `e` und Schritt `s_a`, wird direkt als
  Anwendung des Dedekindschen Satzes erläutert. Sie beschreibt die
  Zahlenkette mit einem festen Buchstaben; wechselnde Buchstaben
  führen zur allgemeinen Wortrekursion.
- Die gesuchte Funktion, ihre Daten und der vollständige Satz stehen
  vor der technischen Existenzkonstruktion. Das Prädikat `WRec` bleibt
  als formale Abkürzung erhalten.
- `WordRecursionTwoSolutionsEqual` wird aus dem Abschnitt über die
  kanonische Darstellung vorgezogen und direkt durch Wortinduktion
  bewiesen. Dieser Beweis verwendet keinen Existenzsatz.
- Die Existenz wird in einem eigenen Unterabschnitt auf die
  Zahlenrekursion zurückgeführt. Der Zustand einer Aufbauphase ist
  eine Teilmenge von `W × X`. Der Operator bildet das Anfangspaar und
  die Fortsetzungen der vorliegenden Paare. Die Vereinigung seiner
  durch `RecFun` erzeugten Stufen liefert die gesuchte Funktion.
- Die Einleitungen unterscheiden Zahleninduktion über Stufen von
  Wortinduktion über Wörter. Die Konstruktion benutzt weder eine
  vorausgesetzte abstrakte Wortlänge noch einen späteren Isomorphismus.
- Die kanonische Darstellung wird als Übersetzung zwischen zwei
  Wortstrukturen erklärt. Die Einführung nichtleerer Rekursion und
  Linksfaltung erläutert Anfangswerte je Buchstabe. Die Baumrekursion
  erklärt den Übergang zu zwei Teilbaumwerten und behält ihren eigenen
  Schnittbeweis.
- Die Übersicht zu Band 27 in Band 00 unterscheidet nun korrekt den
  Stufenbeweis für Wörter vom Schnittbeweis für Bäume.

## Erhaltene Schnittstellen und historische Berichte

Die später verwendeten Resultate `WordRecursionSpecificationDef`,
`WordRecursionTwoSolutionsEqual`, `WordStructureRecursionGraphFunction`,
`WordStructureRecursionGraphEquations`, `WordStructureRecursion` und
`FiniteWordRecursion` behalten ihre Kennungen und benötigten Aussagen.
Die entfernten Schnitt- und Faserhilfssätze der Wortrekursion haben keine
aktiven Verwendungen außerhalb ihres bisherigen Beweisabschnitts.
Die allgemeinen Faserfilter der früheren Bände bleiben für den
Baumrekursionsbeweis erhalten.

Berichte vom 13. September, insbesondere
`band27-verbleibende-saetze-2026-09-13.md`, beschreiben den damaligen
Schnittbeweis. Ihre Einstufung der Wortrekursions-Hilfssätze als benötigt
ist durch diese Umsetzung überholt; die Berichte bleiben als historische
Prüfstände erhalten.

## Prüfung

- Unabhängige inhaltliche Gegenprüfung des Stufenbeweises und der
  Übersetzung von Band 10: keine vorausgesetzte abstrakte Wortlänge,
  kein Rückgriff auf den späteren Isomorphismus und kein Zirkelschluss.
  Leere und unendliche Alphabete sind berücksichtigt. Die Stufen werden
  von natürlichen Zahlen gezählt, müssen aber keine endlichen Mengen sein.
- Statische Quellenprüfung: 455 Beweiszeilen in 27 Beweisen der drei
  Rekursions- und Darstellungsdateien; keine Befunde bei Klammern,
  Umgebungen, Rückverweisen auf Beweiszeilen, Annahmenkennungen und
  verwendeten Regelmakros. Dies ist keine maschinelle Zertifizierung
  der mathematischen Gültigkeit.
- Die formale Gegenprüfung berücksichtigte insbesondere die Richtung
  von Gleichheitsersetzungen, die lokalen Annahmen bei Zahlen- und
  Wortinduktion sowie die Entladung von Existenzzeugen.
- Der Kettenbeweis verwendet die aktive Fassung
  `B04PeanoStrictMonotoneAddOne` in Band 10. Die Umrechnung
  von `Succ(k)` nach `k+1` ist mit `PeanoAddOneSucc` ausgeführt.
- Die PDF-Sichtprüfung erfasst die neu formulierten Abschnitte und
  Übergänge. Dabei erkannte überbreite Formelzeilen wurden umbrochen;
  Satzüberschriften, Variablendaten und Aussagen werden bei Bedarf
  gemeinsam auf die nächste Seite gesetzt.
- Die Textkontrolle in `scripts/publish-pdfs.py` nutzt vorhandenes
  `pdftotext` mit `-raw` und UTF-8. Fehlt das Programm, bleibt die
  bisherige pypdf-Auswertung erhalten. Fehlerausdrücke, Seitenzuordnung
  und alle Build- und Linkprüfungen bleiben erhalten. Die Seitenanzahl
  wird zusätzlich mit pypdf abgeglichen. Vierzehn positive PDF-Testfälle
  einschließlich umgebrochener Fehler in mehrspaltigen Formeln liefern
  in beiden Verfahren identische Meldungen und Seitenzahlen; negative
  Fälle, leere Endseiten, Fallback und Abbruch bei Prozess- oder
  Seitenzählfehlern sind geprüft. Am 245-seitigen Band 27 sank die
  reine Textprüfzeit von 17,79 auf 5,16 Sekunden.

Der vollständige PDF-Neubau und die Abschlussprüfungen sind abgeschlossen:

- Alle 49 Einzelbände B00 bis B48 und der Gesamtband wurden neu gesetzt.
  Band 27 umfasst 245 PDF-Seiten, der Gesamtband 2.839 PDF-Seiten.
- Die Verweisprüfung bestand für jeden Einzelband und den Gesamtband.
  Ergebnisindizes und Satznummern stimmen zwischen beiden Ausgaben
  überein; es bleiben keine fehlgeschlagenen Formelverweise offen.
- Nach den Umbruchkorrekturen wurden die überarbeiteten Abschnitte von
  Band 27 und alle acht zugehörigen Übersichtsseiten visuell geprüft.
  Zusätzlich wurden 22 ausgewählte Seiten des fertigen Gesamtbands
  und die Einstiegsseiten der tatsächlich ausgegebenen PDFs geprüft.
  In diesen Bereichen wurden keine abgeschnittenen oder überlappenden
  Inhalte und keine getrennten Satzüberschriften mit ausgelagerten
  Aussagen mehr gefunden.
- Alle 50 PDFs liegen aktualisiert unter `output/`. Die abschließende
  Prüfung der ausgegebenen Dateien bestand für 66.356 lokale und
  38.624 externe PDF-Verknüpfungen.

Die ausführlichen technischen Prüfprotokolle und gerenderten Seiten
liegen unter `tmp/b27-stufen-qa/`, insbesondere
`proof-source-check.json`, `final-audit.console.log`,
`publish.console.log` und `benchmark-publication-audit.json`.
