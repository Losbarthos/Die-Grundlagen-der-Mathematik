# Formale Differenzen: Lesefassung und Beweistabellen

Stand: 21. September 2026.

Umgesetzt ist die Empfehlung aus [der inhaltlichen Sichtung](lesefassungen-sichtung-und-naechstes-thema-2026-09-21.md): eine Lesefassung zum Einbettungssatz für kommutative kürzbare Monoide, zusammen mit einem eigenständigen Beweisband. Im anschließenden Ausbau erhielt Band 17 eine eigene Lesefassung bis zur Ganzzahlaxiomatik; die Lesefassung zu Band 41 wurde darauf abgestimmt. Dieser Ausbau ist [separat dokumentiert](ganze-zahlen-auslagerung-2026-09-21.md). Die danach ergänzten Tabellen zum Produktbeispiel, zum Maximum-Gegenbeispiel und zu den notwendigen Einbettungsbedingungen beschreibt der [Nachtrag zu den Tabellenbeweisen](formale-differenzen-ergaenzende-tabellenbeweise-2026-09-21.md).

## Ausgaben und Inhalt

- [Lesefassung](<../output/08 Gruppen/Ergänzungen/Formale Differenzen/Bd. 41 - Formale Differenzen - Lesefassung.pdf>): „Wie aus Monoiden Gruppen werden“, 11 PDF-Seiten einschließlich Titelblatt. Sie führt von einem allgemeinen kommutativen kürzbaren Monoid über Paare, Äquivalenzklassen, Repräsentantenunabhängigkeit und inverse Klassen zur injektiven Einbettung. Das Beispiel zweier unabhängiger Richtungen und ein Gegenbeispiel ohne Kürzbarkeit verdeutlichen Reichweite und Voraussetzungen des Satzes. Zwei TikZ-Diagramme veranschaulichen die Klassen im Paargitter und die Erhaltung der Operation. Die zusätzlichen Ergebnisse verweisen direkt auf ihre Tabellenbeweise.
- [Beweistabellen](<../output/08 Gruppen/Ergänzungen/Formale Differenzen/Bd. 41 - Formale Differenzen - Beweistabellen.pdf>): 106 PDF-Seiten einschließlich Titelblatt und verlinktem Lesepfad. Der Band enthält die gesamte aus Band 41 ausgelagerte Konstruktion mit 28 Tabellen und 102 zusätzliche Tabellen in drei weiteren Kapiteln. Die erste Auslagerung allein umfasste 29 Seiten.

Die Lesefassung beweist die entscheidenden Übergänge selbst. Sie setzt keine bereits definierte Subtraktion voraus und behandelt die additive Struktur; Multiplikation, Ordnung und eine universelle Eigenschaft werden nicht als zusätzliche Ergebnisse beansprucht.

## Aufteilung und unveränderte Referenzen

Band 41 und der Gesamtband behalten den kanonischen Einbettungssatz `GroupCompletionEmbeddingTheorem` mit Nummer **41.4.5.4**. Der Hauptsatz wird im Beweisband nur referenziert; sein vollständiger Schlussbeweis steht dort unter dem Ziel `differences.proof`.

Die sieben Definitionen, 26 Hilfssätze und zehn benannten Teilresultate der Konstruktion gehören ausschließlich zum Beweisband. Ihre 43 semantischen IDs bleiben erhalten, ihre Nummern beginnen jetzt mit **41E**. Die Definitionen besitzen jeweils einen Registereintrag für den Quellschlüssel und einen für die normalisierte Formel; insgesamt enthält das Migrationsmanifest deshalb 40 strukturelle Registerzeilen und 43 ID-Zeilen.

Der Nachtrag fügt 111 lokale Aussagen und Definitionen hinzu. Insgesamt besitzt der Beweisband damit 154 semantische IDs; das Migrationsmanifest der ursprünglichen Konstruktion bleibt unverändert.

Der verkürzte Hauptband beschreibt die benötigten Objekte und Operationen in Prosa und verlinkt ihre formalen Definitionen und Beweise. Alle fünf bisherigen Abschnitte bleiben erhalten. Reservierte Formelanker sichern die ursprünglichen Sprungziele der verbleibenden Aussagen:

- Einbettungssatz: `41.4.5.4`, Ziel `section*.47`.
- Additive abelsche Gruppe der ganzen Zahlen: `41.5.1`, Ziel `section*.48`.
- Auch die drei zugehörigen Teilbeweisanker und alle übrigen öffentlichen IDs bleiben unverändert.

Die Beweise der grundlegenden Ganzzahlkonstruktion aus Band 17 liegen inzwischen in einem eigenen Ergänzungsband mit Präfix **17E**; die öffentlichen Aussagen bleiben in Band 17. Die Überblickstexte zu Band 17 und 41 erschließen beide Ergänzungspaare. Für die aus Band 41 ausgelagerten IDs wurde außer dem Überblick kein weiterer aktiver Verbraucher gefunden. Insbesondere benötigt Band 43 wegen der erhaltenen Nummer und des erhaltenen Ankers des Ganzzahlgruppensatzes keinen Neubau.

## Quellen und Bau

Die Quellen liegen unter `tex/b41/differences/`, die Einstiegspunkte unter `editions/b41-differences-reading.tex` und `editions/b41-differences-proofs.tex`. `tex/impl/differences-editions.tex` stellt die Verknüpfungen bereit und wird von `main.tex` geladen.

Der gezielte Bau erfolgt mit:

```powershell
./scripts/build-differences-editions.ps1
```

Dieser baut Band 41, beide Ergänzungen, den Überblick und den Gesamtband, prüft die Dokumente und aktualisiert die veröffentlichten PDFs. `-EditionsOnly` baut die Ergänzungen aus vorhandenen aktuellen Bandartefakten. `-SkipMain` und `-SkipPublish` lassen die jeweiligen Schritte aus.

Die Ergänzungen sind auch in `build-all.ps1`, `publish-pdfs.py`, dem Quellaudit, README, Bandverzeichnis und Bauanleitung berücksichtigt. Der Veröffentlichungsordner ist `output/08 Gruppen/Ergänzungen/Formale Differenzen/`.

## Prüfung

Der Lesetext und seine Diagramme wurden unabhängig mathematisch gegengelesen. Die Argumente zur Transitivität, zur Repräsentantenunabhängigkeit beider Operanden, zur Gruppenstruktur, zur Einbettung und zur Verallgemeinerung sind vollständig ausgeführt.

Bei der ersten Auslagerung wurden alle 28 Tabellenkörper gegen den gesicherten Originaltext verglichen; sie waren abgesehen von Leerraum und zusätzlich eingefügten Linkankern identisch. Der spätere Nachtrag berichtigt drei unmittelbar verwendete Tabellen zu Klassenmitgliedschaft, Klassengleichheit und Paarrepräsentanten. Die 25 anderen Tabellen bleiben gegenüber diesem Ausgangsstand unverändert. Aussagen und IDs der ursprünglichen Konstruktion bleiben erhalten; die gezielten Beweiskorrekturen sind im Nachtrag einzeln dokumentiert.

Das automatisierte Editionsaudit prüft die ursprünglichen Formeln, Titel und Identitäten gegen das Migrationsmanifest, den getrennten Registerbesitz, den Erhalt der öffentlichen Nummern und Anker, die gefilterten Importe sowie die PDF-Ziele und Verknüpfungen. Die neue Lesefassung und der Beweisband haben keine überbreiten Formelzeilen und keine undefinierten Verweise. Sämtliche Seiten der beiden Ergänzungen wurden gerendert und visuell geprüft; Diagramme und die zuvor auffälligen Beweisseiten zusätzlich im Detail.

Diese Prüfungen sichern die dokumentierte Auslagerung und die Lesbarkeit. Sie sind keine maschinelle Verifikation der logischen Schlussregeln.

## Gesamtband und Veröffentlichung der ersten Auslagerung

Nach der ersten Auslagerung aus Band 41 wurden Band 41, der Überblick und der Gesamtband vollständig neu gebaut. Dieser Zwischenstand des Gesamtbands umfasste 2.736 PDF-Seiten. Das reguläre Bauaudit hat für Band 41, Band 00 und den Gesamtband bestanden; insbesondere stimmten die Ergebnisregister und Satznummern der Gesamtausgabe mit den Einzelausgaben überein. Auch die geänderten Kapitel- und Überblicksseiten im Gesamtband wurden gerendert und visuell geprüft. Den neueren Stand nach der anschließenden Auslagerung aus Band 17 dokumentiert der [Ganzzahlbericht](ganze-zahlen-auslagerung-2026-09-21.md).

Die beiden Ergänzungen sowie die aktualisierten PDFs von Band 41, dem Überblick und dem Gesamtband sind in der bestehenden thematischen Struktur unter `output/` veröffentlicht.

Die damalige Linkprüfung der veröffentlichten Sammlung hat bestanden: **60 PDFs mit 5.665 Seiten, 64.360 lokalen und 38.829 externen Verweisen**. Dazu gehörten sämtliche Verknüpfungen der damaligen Ergänzungen untereinander und mit den Hauptbänden.
