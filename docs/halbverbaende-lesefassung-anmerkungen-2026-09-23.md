# Band 45: Anmerkungen zur Lesefassung

Stand: 23. September 2026.

Die angehängte, einseitige PDF zeigt die gedruckte Seite 10 der bisherigen Lesefassung. Die handschriftliche Anmerkung wünscht eine Schlussbemerkung beziehungsweise Zusammenfassung sowie eine historische Einordnung: Wie ist die Idee entstanden? Der Hinweis auf andere Bände wurde als Wunsch nach einer entsprechenden Ergänzung dieser Lesefassung aufgegriffen.

## Umsetzung

In [reading.tex](../tex/b45/semilattice/reading.tex) wurden zwei Abschnitte ergänzt:

- **Wie die Verbindung historisch entstand:** Klassenlogik, Teilbarkeit und Dedekinds Dualgruppen führen zur abstrakten Verbindung von Verknüpfungen und Ordnung. Das Beispiel `a | b ⇔ kgV(a,b) = b` auf den positiven ganzen Zahlen macht die Motivation anschaulich. Birkhoffs Arbeiten verbinden den historischen Rückblick unmittelbar mit der Leitgleichung der Lesefassung.
- **Schlussbemerkung:** Zusammenfassung der beiden Konstruktionen, ihrer wechselseitigen Rückgewinnung und der zusätzlichen Voraussetzungen für ein kleinstes Element oder unendliche Suprema.

Die historischen Angaben sind durch verlinkte Fußnoten belegt. Untersucht wurden insbesondere Dedekinds eigener Bericht über den Ausgangspunkt seiner Forschung und die ausdrückliche Definition einer Ordnung durch eine Verknüpfung:

- [Schröder, *Vorlesungen über die Algebra der Logik*, Band I (1890)](https://www.deutschestextarchiv.de/book/show/schroeder_logik01_1890); die Zuordnung der betreffenden Gesetze ist zusätzlich durch Dedekinds Verweise auf S. 112 der folgenden Quelle belegt.
- [Dedekind, *Über Zerlegungen von Zahlen durch ihre größten gemeinsamen Teiler* (1897)](https://rcin.org.pl/Content/140714/PDF/WA35_171681_15883-2_Art9.pdf), Werkereprint, Band II, besonders S. 108–114.
- [Dedekind, *Über die von drei Moduln erzeugte Dualgruppe* (1900)](https://rcin.org.pl/Content/140716/PDF/WA35_171699_15883-2_Art11.pdf), Werkereprint, Band II, besonders S. 236–238.
- [Birkhoff, *On the combination of subalgebras* (1933)](https://doi.org/10.1017/S0305004100011464), Einleitung, sowie [*On the structure of abstract algebras* (1935)](https://doi.org/10.1017/S0305004100013463), S. 435, Fußnote §.

Eine Prioritätsbehauptung zur erstmaligen Entdeckung des Halbverbands wird nicht aufgestellt. Der Text unterscheidet die historische Entwicklung der Theorie mit zwei Verknüpfungen von der Konzentration dieser Lesefassung auf eine einzige Operation.

## Ergebnis und Prüfung

Die aktualisierte [Lesefassung](../output/05%20Ordnungen%20und%20Verbände/Ergänzungen/Halbverbände%20und%20Ordnung/Bd.%2045%20-%20Halbverbände%20und%20Ordnung%20-%20Lesefassung.pdf) umfasst **13 PDF-Seiten einschließlich Titelblatt**. Die Ergänzungen stehen auf den gedruckten Seiten 11 und 12.

Die neuen Abschnitte wurden unabhängig historisch und mathematisch gegengelesen und anschließend visuell geprüft. Ein Vergleich der gerenderten Seiten bestätigt, dass die bisherigen elf PDF-Seiten unverändert sind. Ein ungünstiger Umbruch innerhalb der historischen Leitgleichung wurde behoben; der Birkhoff-Absatz beginnt nun vollständig auf der letzten Seite.

LuaLaTeX-Bau und Editionsaudit sind erfolgreich. Alle 23 ursprünglichen Aussagen und Beweistabellen sowie sämtliche kanonischen Kennungen, Nummern und Ziele von Band 45 bleiben erhalten. Alle bisherigen Sprungziele der Lesefassung bestehen weiter. Die neue PDF hat keine übervollen oder untervollen Textboxen und keine undefinierten Verweise im Build-Protokoll.

Die Veröffentlichung verwendet die vorhandenen Pfadumschreibungs- und Prüffunktionen des PDF-Publishers. Der Seiteninhalt stimmt mit der visuell geprüften Bauausgabe überein; die Prüfung der 13 internen und 36 externen PDF-Verweise ist bestanden. Die historischen Quellen sind zusätzlich als Weblinks hinterlegt.
