# Beweistabellen und Isomorphiebeispiele

Die Prüfung umfasst die aktiven Bände B00–B44 einschließlich des neu eingebundenen Abschnitts `tex/B28-isomorphism-examples.tex`. B00 enthält keine Beweise. Historische Archivfassungen gehören nicht zur aktiven Ausgabe.

## Isomorphismen in Band 28

Der Abschnitt **Beispiele von Isomorphismen** unterscheidet positive Produktpotenzen des Halbgruppenträgers von kartesischen Potenzen. Er behandelt Umkehrabbildungen und Einschränkungen, Unterhalbgruppen und Ideale, Erzeugnisse, Hauptideale und Green-Relationen, endliche Potenzhalbgruppen, direkte Produkte und Umindizierung, Gegenhalbgruppen, Zentralisatoren und Zentren, lokale Träger, Einheiten und Adjunktionen, Kongruenzen und Quotienten einschließlich Rees-Quotienten, Endomorphismen und Automorphismen sowie Inklusionsordnungen und Gleichungslösungen.

Die Beweise führen die jeweils benötigten Abbildungs-, Abschluss-, Homomorphie- und Bijektivitätseigenschaften getrennt aus. Zusätzliche Hilfssätze decken insbesondere abgeschlossene Teilträger, Produkte von Halbgruppen und die Endlichkeit von Mengenprodukten ab. Bei Gleichungslösungen wird eine Bijektion der Lösungsmengen behauptet; eine allgemeine Abgeschlossenheit dieser Mengen unter der Halbgruppenoperation wird nicht vorausgesetzt.

## Gemeinsame Darstellung

- Normale und breite Beweistabellen verwenden eine feste Begründungsspalte. Eine vollständige Aussage und ihre Begründung beginnen auf derselben Grundlinie.
- Die historischen Inline-/Break-Varianten delegieren auf dieselbe zentrale Implementierung. Lokale Umdefinitionen und der besondere Mogiljanskaja-Zeilenbefehl umgehen diese Darstellung nicht mehr.
- Mehrzeilige Formel- und Referenzblöcke sind oben ausgerichtet. Lange Referenz- und Abhängigkeitslisten erhalten Umbruchstellen.
- 52 über mehrere Zeilen zentrierte Begründungsfelder wurden auf die erste Aussagezeile ausgerichtet. Lange Textbegründungen bleiben innerhalb der eigenen Spalte umbrechbar.
- Die Schrittspalte bietet auch dreistelligen Nummern Platz; dafür wird allein die Grenze zwischen Abhängigkeiten und Schrittzahlen verschoben. Formel- und Begründungsspalte behalten ihre Position.
- Einschübe in Gleichungsketten werden durch eine ausdrücklich wiederholte linke Seite lesbar gehalten.

## Redaktion der Beweise

Die Prämissenprüfung berücksichtigt sowohl geschachtelte `FormulaRefAuto`-Argumente als auch alte, mit `makecell` und wörtlichen Klammern gesetzte Theoremanwendungen. Konkrete zuvor versteckte Zwischenaussagen erhalten eigene nummerierte Zeilen. Nachfolgende Argumentindizes, Abhängigkeiten und Fortsetzungszähler werden entsprechend angepasst.

Mehrteilige Nachweise sind nach den tatsächlich zu zeigenden Eigenschaften gegliedert, beispielsweise Existenz/Eindeutigkeit, Hin-/Rückrichtung, Abschluss/Operationserhaltung/Bijektivität oder Induktionsanfang/Induktionsschritt. Bereits vorhandene registrierte Teilresultate behalten ihre Referenzidentität.

Dabei gefundene inhaltliche Fehler wurden ebenfalls berichtigt: fehlende Annahmezeilen, veraltete Selbst- und Vorwärtsverweise, falsche Trägervoraussetzungen, eine Anwendung der Gleichheitssymmetrie auf eine Ungleichheit und ausgelassene Schritte in Graphen- und Ordnungsbeweisen. Einzelheiten stehen in den Teilberichten:

- [B01–B21](proof-audit-b01-b21.md)
- [B22–B44](proof-audit-b22-b44.md)
- [Band 28: Isomorphieregeln und ältere Beweise](proof-audit-b28-isomorphism-rules.md)
- [Unabhängige mathematische Gegenprüfung der Konstruktionen](proof-audit-b28-constructions-qa.md)
- [Layoutprüfung B08, B10 und B17](proof-layout-audit-b08-b10-b17.md)

Reine logische Ersetzungsschemata und definitorische Umschreibungen können weiterhin unmittelbar als Schema auftreten. Eine solche Schemareferenz ist von einer bewiesenen Sachprämisse zu unterscheiden. Dasselbe gilt für die Angabe des wiederholt anzuwendenden Satzschemas in einer Wiederholungsregel.

## Prüfmethode

`scripts/proof-source-audit.py` inventarisiert die aktiven Beweiszeilen mit einem klammerbewussten TeX-Scanner. `scripts/proof-edit-tools.py` unterstützt die Übertragung zuvor geprüfter Zwischenzeilen und schützt dabei Theoremschlüssel und Zahlen in mathematischen Formeln vor einer Umnummerierung.

Die Strukturprüfung umfasst ausgeglichene Gruppen und Umgebungen, Fortsetzungsnummern, wörtliche Theoremargumente und die erneute Prüfung verbliebener Kandidaten. Lokale Makros, die mehrere Beweiszeilen erzeugen, werden bei verdächtigen Zeilenverweisen zusätzlich nach ihrer Expansion beurteilt.

Die Prüfung ist eine mathematische und redaktionelle Durchsicht mit ergänzenden Strukturkontrollen, keine Verifikation durch einen formalen Beweisassistenten.

## Ausgabeprüfung

Am 7. September 2026 wurden alle 45 Einzelbände B00–B44 nach den letzten gemeinsamen Satzkorrekturen vollständig neu gebaut. Sämtliche Einzelbände haben die Referenzprüfung bestanden; zusammen umfassen sie 2.468 Seiten.

Band28 enthält einschließlich des neuen Abschnitts 223 Seiten. Sein abschließender Einzellauf enthält keine Overfull- oder Missing-character-Meldungen. Die physischen Seiten 118, 119, 134, 149 und 172 wurden zusätzlich visuell geprüft: Abschnittsbeginn, Umkehrisomorphismus, Produktpotenzen, direkte Produkte und Quotienten. In dieser Stichprobe sind Aussagen und rechte Begründungsspalten vollständig und ohne Überlappungen lesbar.

Der frühere Satzabbruch in B31 ist behoben. Zwei mathematisch gesetzte Textgründe wurden berichtigt und drei lange Aussagezellen umbrochen. B31 wurde danach erneut gebaut und geprüft; die korrigierten Zellen auf physischer Seite 23 sind visuell kontrolliert.

Der Gesamtband wurde nach drei LuaLaTeX-Durchgängen erfolgreich mit 2.441 physischen PDF-Seiten erzeugt. `scripts/audit-build.ps1 -IncludeMain` hat sämtliche Einzelbände und den Gesamtband geprüft. Die registrierten Ergebnisindizes und die tatsächlichen Theoremnummern stimmen zwischen Gesamtband und Einzelbänden überein. Die erste Seite der neuen Isomorphiebeweise wurde auch im Gesamtband visuell kontrolliert (physische Seite 1853).

Alle 46 PDFs wurden am 7. September 2026 unter `output/` aktualisiert: die 45 Einzelbände B00–B44 und der Gesamtband. Die abschließende Prüfung durch `scripts/publish-pdfs.py` hat bestanden: 4.909 Seiten, 55.247 interne Links und 31.113 bandübergreifende Links. Sämtliche geprüften Verknüpfungen führen auf vorhandene Ziele; die externen Dateinamen entsprechen den sichtbaren PDF-Namen im Ausgabeordner. Es sind keine temporären Veröffentlichungsdateien zurückgeblieben.
