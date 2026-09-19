# Cantor–Bernstein: Anmerkungen zur Lesefassung

Stand: 19. September 2026. Grundlage ist das vom Autor handschriftlich
kommentierte PDF „Band 08 - Cantor-Bernstein - Lesefassung.pdf“ mit sieben
PDF-Seiten. Die Markierungen sind in die Seiten eingebettet; deshalb wurden
alle Seiten visuell gelesen und die Anmerkungen unabhängig gegengeprüft.

## Erste Runde: übernommene Korrekturen

- Die unverständliche Pfeilketten-Einleitung wurde durch eine direkte
  Erklärung der beiden Teilabbildungen ersetzt. Ein Schema zeigt die
  Zerlegungen von A und B sowie die Richtung von F und G. Die benötigte
  Bildgleichung wird als Ziel der Konstruktion ausdrücklich benannt.
- Die Erklärung durch „disjunkt markierte Kopien“ entfällt.
- Der mathematische Beweis trägt die gewöhnliche Überschrift „Beweis“.
- Bei der Abgeschlossenheit wird die erste Inklusion aus der Monotonie,
  die zweite ausdrücklich aus der Zugehörigkeit von X zur Familie K
  hergeleitet.
- Die durchgestrichenen Abschnitte „Ableitungsnachweise“ und „Aussagen zum
  Lesebeweis“ einschließlich sämtlicher wiederholter Deklarationen entfallen.
  C wird im Beweis selbst definiert; der Beweis bleibt damit vollständig.
- Der mit „OK“ markierte Anschluss an Band 11 bleibt erhalten.
- „Originalbeweis“ wurde als historischer Beweis verstanden. Eigene
  Abschnitte erläutern Dedekinds Konstruktion, vergleichen sie mit der
  vorliegenden Ausarbeitung und ordnen Bernsteins bei Borel veröffentlichte
  Fassung ein. Beide Originalquellen sind direkt verlinkt.
- Ein kurzer Verweis führt zu den formalen Aussagen in B08 und zu den
  ausführlichen Beweistabellen; die gestrichene Aussagenliste wird dadurch
  nicht nochmals abgedruckt.

## Historische Quellen

- Richard Dedekind: „Ähnliche (deutliche) Abbildung und ähnliche Systeme“,
  Manuskript vom 11. Juli 1887, veröffentlicht in den Gesammelten
  mathematischen Werken III (1932), S. 447–449.
  [Originalscan](https://rcin.org.pl/Content/142326/PDF/WA35_176323_15883-3_Art17.pdf).
- Émile Borel: Leçons sur la théorie des fonctions, Paris:
  Gauthier-Villars et fils, 1898, S. 104–106.
  [Originalscan ab S. 104](https://archive.org/details/leconstheoriefon00borerich/page/n117/mode/2up).
  Borel nennt Bernstein als Urheber und weist auf seine eigene Bearbeitung hin.

Die Schnittkonstruktion wird als Ausarbeitung der Dedekindschen Beweisidee
beschrieben, nicht als neuer Beweis oder als Gegensatz zu allen historischen
Beweisen.

## Technische Umsetzung und Prüfstand der ersten Runde

Die Lesefassung enthält keine eigenen nummerierten Deklarationen mehr.
Ihr gesonderter Import `b08-reading` übernimmt die kanonischen B08-Verweise.
Die Beweistabellen verwenden weiterhin ihren bisherigen gefilterten Import
und behalten alle zwölf Identitäten. B08 und Gesamtband sind von den
inhaltlichen Änderungen der Lesefassung nicht betroffen.

Die Prüfung der 52 vorhandenen Ausgabedateien fand 13 eingehende Links zur
Lesefassung. Alle verwenden das erhaltene Sprungziel `csb.reading`; keiner
verweist auf einen der entfallenen lokalen Aussageanker.

Der angepasste CSB-Audit prüft die neue Trennung, die unveränderten
Beweisidentitäten und die lokalen und dateiübergreifenden PDF-Ziele.
Die korrigierte Lesefassung hat sechs statt sieben PDF-Seiten. Alle sechs
Seiten wurden visuell geprüft; der historische Vergleich beginnt geschlossen
auf einer neuen Seite. Der LuaLaTeX-Build und der CSB-Audit sind bestanden.
Die veröffentlichte Lesefassung stimmt in ihren Seiteninhalten mit dem
geprüften Build-Produkt überein.

Der abschließende Linkaudit aller 52 Ausgabedateien ist bestanden:
5.718 Seiten, 66.279 lokale und 38.729 dateiübergreifende Links.
Die Lesefassung enthält sechs dateiübergreifende Projektverweise sowie
die beiden Weblinks zu den historischen Originalquellen.

## Zweite Anmerkungsrunde

Das erneut kommentierte sechsseitige Nutzerexemplar enthält zwei weitere
Anmerkungen, auf PDF-Seite 3 und PDF-Seite 6. Beide wurden unabhängig gelesen.

- Die Komplementgleichung wird nun mit der De-Morganschen Regel in drei
  Zeilen hergeleitet. Dabei wird erklärt, wo `G[B] ⊆ A` eingeht. Auch der
  in der Randnotiz vorgeschlagene zusätzliche Schnitt `A ∩ G[F[C]]` wird
  ausdrücklich als gleichwertig erklärt, weil `G[F[C]] ⊆ A` gilt.
- Der Abschnitt zu Bernstein/Borel definiert die absteigende Folge, ihre
  Differenzschichten und den gemeinsamen Rest. Er erklärt die Verschiebung
  der geraden Schichten, das Festhalten der ungeraden Schichten und des Rests
  unter der Hilfsabbildung sowie die anschließende Umkehrung von G. Der
  Zusammenhang `E = C` mit der Schnittkonstruktion wird begründet.

Die ergänzte Schichtenkonstruktion wurde unabhängig mathematisch geprüft.
Die aktualisierte Lesefassung hat sieben PDF-Seiten. Der LuaLaTeX-Build und
der CSB-Audit sind bestanden; alle sieben Seiten wurden visuell geprüft.
Definition und Begründung der Schichtenabbildung stehen zusammen auf einer
Seite. Die veröffentlichten Seiteninhalte stimmen mit dem geprüften
Build-Produkt überein.

Alle acht bisherigen benannten Sprungziele der Lesefassung bleiben erhalten.
Der gezielte Ausgabeaudit prüft erfolgreich ihre sechs dateiübergreifenden
Projektverweise. Die übrigen PDFs wurden in dieser Runde nicht verändert.
