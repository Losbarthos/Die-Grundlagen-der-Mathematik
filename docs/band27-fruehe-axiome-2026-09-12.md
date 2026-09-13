# Band 27: Frühe Strukturaxiome und Abhängigkeitsrichtung

Diese Fortführung ordnet die Strukturaxiome unmittelbar nach den
konkreten Nachweisen ein. Sie ersetzt die frühere Anordnung als
Schlusskapitel und die Herleitung abstrakter Rekursion durch Transport
bereits bekannter konkreter Rekursion.

## Wortaufbau

1. Endliche Mengen markierter Vorkommen in `N × A`, Wortlänge als
   endliche Kardinalität und die primitive Anfügung
   `σ_A(u,a) = u ∪ {(|u|,a)}` werden vor der Konkatenation eingeführt.
2. Die konkreten Eigenschaften W0–W2 folgen aus den Vorkommenspositionen.
   W3 folgt aus der Kardinalitätsinduktion von Band 20
   (`EarlyWordModelMinimality`). Allgemeine Wortinduktion oder
   Wortrekursion werden dabei nicht vorausgesetzt.
3. `WordStructureDef` bündelt W0–W3. `WordStructureConcreteModel`
   bestätigt das vorhandene Modell. Die registrierten Axiome sind
   Zugriffsregeln auf diese Strukturbedingungen.
4. Zerlegung und Induktion folgen aus den Wortaxiomen.
   `WordStructureRecursion` konstruiert den kleinsten unter Anfangs-
   und Schrittregel abgeschlossenen Relationsgraphen in `W × X`.
   Trennung und Injektivität sichern eindeutige Werte; W3 erreicht den
   gesamten Träger. Der Beweis benutzt keine konkrete Wortrekursion
   und keinen zuvor konstruierten kanonischen Isomorphismus.
5. `FiniteWordRecursion` ist die Anwendung auf das konkrete Modell.
   Die Rekursion nichtleerer Wörter folgt daraus über Einzelmengenwerte
   in `P(X)`. Spätere Wortinduktionen, Zerlegungen,
   Konkatenationsgesetze und Faltungen verwenden diese Grundlage.

## Baumaufbau

1. Blatt- und Knotencodes sowie ihre Erzeugungsstufen werden konstruiert.
   Die konkreten Nachweise von B0–B3 verwenden die Codeeigenschaften.
   `TreeCodeMinimality` beweist B4 durch natürliche Induktion über die
   Stufen, ohne bereits Bauminduktion vorauszusetzen.
2. `BinaryTreeStructureDef` und `BinaryTreeStructureConcreteModel`
   führen das erfüllte System B0–B4 ein. Daraus folgen allgemeine
   Zerlegung und Strukturinduktion.
3. `BinaryTreeStructureRecursion` wird unmittelbar mit dem kleinsten
   unter Blatt- und Knotenregeln abgeschlossenen Relationsgraphen
   bewiesen. Die konkrete Baumrekursion ist anschließend ein Korollar.
4. Blattwort, Klammerung, Auswertung und die späteren kanonischen
   Strukturisomorphismen bauen auf dieser Rekursion auf.

Die Axiome postulieren keine zusätzlichen Mengen. Beim leeren Alphabet
enthält jede Wortstruktur nur ihren Anfang; jede freie beschriftete
Binärbaumstruktur ist leer. Die Rekursionsbeweise berücksichtigen diese
Fälle ohne Wahl eines zusätzlichen Zielwertes. Für Band 48 wird das
Beweismuster übernommen; unterschiedliche Syntaxkonstruktoren und ihre
Stelligkeiten bleiben von der binären Codierung unterschieden.

## Prüfstatus der neu geordneten Fassung

- Die konkreten Modellnachweise, die unmittelbaren abstrakten
  Rekursionsbeweise und ihre späteren Anwendungen wurden unabhängig
  mathematisch gegengelesen. Dabei wurden auch das leere Alphabet und
  die Rekursion nichtleerer Wörter mit möglicherweise leerer Zielmenge
  berücksichtigt.
- Die rekursive Prüfung der tatsächlich eingebundenen Quellen erfasst
  39 Dateien, 387 benannte Deklarationen und 1156 benannte Verweise.
  Sie findet keine fehlenden oder doppelten Deklarationen und keine
  Verweise auf später eingeführte Ergebnisse.
- Band 27 wurde mit LuaLaTeX/latexmk neu erstellt und umfasst 201 Seiten.
  Die geänderten Beweisblöcke und Axiome sowie Inhaltsverzeichnis,
  Einleitung und Schlusskapitel wurden in gerenderten Seiten kontrolliert.
  Die Verweisprüfung besteht mit 2594 externen Verknüpfungen zu
  197 verschiedenen Zielen.
- Überblick, Bände 28 bis 46 und Band 48 wurden mit den neuen
  Satznummern erstellt und einzeln geprüft. Zusätzlich wurden der
  Band-27-Überblick und die Formelstellen-Brücke in Band 48 visuell
  kontrolliert.
- Die Ausgaben im Ordner `output` wurden aktualisiert. Die abschließende
  Verknüpfungsprüfung sämtlicher 49 Einzelband-PDFs besteht:
  2791 Seiten, 13492 interne und 36555 externe Verknüpfungen.
- Die Gesamtfassung wurde mit 2762 Seiten neu erstellt. Ihr Abgleich
  mit allen 49 Einzelband-Registern und deren Satznummern besteht;
  sie enthält keine externen PDF-Verknüpfungen. Sechs Stichprobenseiten
  mit beiden Strukturdefinitionen, allen neun Einzelaxiomen und den
  Anfängen der beiden abstrakten Rekursionssätze wurden visuell geprüft.
  Die Gesamt-PDF wurde nach erfolgreicher Prüfung ihrer 50097 internen
  Verknüpfungen ebenfalls nach `output` übernommen.

Die Prüfprotokolle und gerenderten Kontrollseiten liegen unter
`tmp/b27-early-axioms/`; die Quellen vor dieser Umordnung sind dort
unter `before/` gesichert.
