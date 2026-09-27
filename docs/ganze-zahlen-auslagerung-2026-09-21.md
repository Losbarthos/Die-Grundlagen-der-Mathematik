# Ganze Zahlen: Lesefassung, Beweisband und Abstimmung mit Band 41

Stand: 21. September 2026.

Nachtrag vom 22. September: Die Lesefassung wurde anhand der Randanmerkungen
überarbeitet und um einen historischen Rückblick ergänzt. Sie umfasst nun
20 Seiten. Die unten genannten 17 Seiten beziehen sich auf den ursprünglichen
Stand; die Änderungen dokumentiert der
[Bericht zur Überarbeitung](ganze-zahlen-lesefassung-randanmerkungen-2026-09-22.md).

Die Ganzzahlkonstruktion aus Band 17 besitzt jetzt eine eigene Lesefassung und einen Ergänzungsband mit den vollständigen Beweistabellen bis zum Modellnachweis der Ganzzahlaxiomatik. Die Lesefassung zu Band 41 wurde auf den allgemeinen Einbettungssatz ausgerichtet. Beide Texte verwenden dieselbe Paar- und Klassennotation, erläutern ihre unterschiedlichen Voraussetzungen und verweisen aufeinander.

## Die beiden Lesefassungen

Die neue [Lesefassung zu Band 17](<../output/04 Zahlen und Folgen/Ergänzungen/Ganze Zahlen/Bd. 17 - Ganze Zahlen - Lesefassung.pdf>) trägt den Titel **Wie die ganzen Zahlen entstehen** und den Untertitel **Von Differenzenpaaren zur Axiomatik**. Sie umfasst 17 PDF-Seiten einschließlich Titelblatt. Ihre neun Abschnitte führen durch:

1. die Motivation für negative Zahlen;
2. Differenzenpaare, Kreuzsummenrelation und Äquivalenzklassen;
3. die Einbettung der natürlichen Zahlen;
4. Negation, Addition und Subtraktion;
5. die Konstruktion und Repräsentantenunabhängigkeit der Multiplikation;
6. die Vorzeichenformen aller ganzen Zahlen;
7. die Ordnung und ihre Verträglichkeit mit der Arithmetik;
8. Schritte um eins, Diskretheit und zweiseitige Induktion;
9. den Modellnachweis und den Übergang zur vollständigen Ganzzahlaxiomatik.

Der Text erklärt die entscheidenden Argumente selbst. Paarmodell und abstrakte Axiomatik werden auseinandergehalten. Insbesondere wird aus einem erststufigen Induktionsschema keine Eindeutigkeit aller Modelle behauptet. Zwei TikZ-Diagramme zeigen die Klassen im Paargitter und die beiden von null ausgehenden Zahlenstrahlen.

Die [Lesefassung zu Band 41](<../output/08 Gruppen/Ergänzungen/Formale Differenzen/Bd. 41 - Formale Differenzen - Lesefassung.pdf>) heißt jetzt **Wie aus Monoiden Gruppen werden** mit dem Untertitel **Formale Differenzen und der Einbettungssatz**. Sie umfasst 10 PDF-Seiten einschließlich Titelblatt und beginnt mit einem beliebigen kommutativen kürzbaren Monoid. Die acht Abschnitte behandeln Voraussetzungen, Differenzenrelation, Operation auf Klassen, Gruppenaxiome und die injektive Einbettung. Das Beispiel der zwei unabhängigen Richtungen führt von natürlichen Zahlenpaaren zu ganzen Zahlenpaaren. Ein Gegenbeispiel mit der Maximumoperation zeigt, weshalb die Kürzbarkeit gebraucht wird.

Band 17 entwickelt damit das vollständige Zahlensystem einschließlich Multiplikation, Ordnung und Induktion. Band 41 verallgemeinert dessen additives Konstruktionsprinzip. Die Monoidvoraussetzungen liefern für sich keine Multiplikation, Ordnung oder Ganzzahlinduktion. Beide Lesefassungen sind auch einzeln lesbar; der natürliche Lesepfad führt von Band 17 zu Band 41.

## Auslagerung und öffentliche Aussagen

Der [Beweisband zu Band 17](<../output/04 Zahlen und Folgen/Ergänzungen/Ganze Zahlen/Bd. 17 - Ganze Zahlen - Beweistabellen.pdf>) enthält auf 102 PDF-Seiten **alle 94 Tabellenbeweise** der Konstruktion bis einschließlich des Modellnachweises. Die erste Auslagerung umfasste 101 Seiten; die unten dokumentierte Nachprüfung ergänzt drei Tabellen. In Band 17 bleibt keine Beweistabelle zurück; der Fachband umfasst 25 Seiten.

Das Migrationsmanifest erfasst die 222 ursprünglichen semantischen IDs. Davon bleiben **85 öffentliche IDs** in Band 17. Hierzu gehören sämtliche 35 Axiome, die drei Axiomenzusammenstellungen und die in anderen Bänden verwendeten Schnittstellenaussagen. Die **137 privaten IDs** der Konstruktion, darunter 74 benannte Teilresultate, gehören nun dem Ergänzungsband und tragen den Nummernpräfix **17E**.

Die Nummern und PDF-Sprungziele aller öffentlichen Aussagen bleiben exakt erhalten. Das gilt auch für den Modellnachweis `IntQuotientModelsIntegerPeano` mit Nummer **17.5.2.1**. Öffentliche Aussagen werden im Ergänzungsband zum Verständnis erneut angezeigt, dort aber nicht nochmals als eigene Ergebnisse registriert. Ihr Beweis steht jeweils unter einem eindeutigen Ziel `integers.proof.<ID>`.

Die Abhängigkeitsprüfung fand **69 öffentliche IDs**, die von anderen aktiven Quellen oder gebauten Fachbänden verwendet werden. Diese Aussagen bleiben erreichbar. Band 17 enthält deshalb neben der Axiomatik eine kompakte Schnittstelle zum konkreten Modell und öffentliche Folgerungen. Insbesondere können bestehende Modellverweise späterer Bände erhalten bleiben, ohne diese Bände inhaltlich umzuschreiben.

## Quellen und Bau

Die neuen Quellen liegen unter `tex/b17/integers/`; die Einstiegspunkte heißen `editions/b17-integers-reading.tex` und `editions/b17-integers-proofs.tex`. `tex/impl/integers-editions.tex` stellt die Verweise für Hauptband, Überblick und Ergänzungen bereit. Der Überblick zu Band 17 erschließt beide Ergänzungen und den Anschluss an Band 41.

Der gezielte vollständige Bau erfolgt mit:

```powershell
./scripts/build-integers-editions.ps1
```

Er baut Band 17, die beiden Ganzzahlergänzungen, die Ergänzungen zu Band 41, den Überblick und den Gesamtband, prüft die Ergebnisse und veröffentlicht sie. `-EditionsOnly` baut und prüft nur die beiden Ganzzahlergänzungen aus bereits aktuellen Bandartefakten. `-SkipMain` und `-SkipPublish` lassen die jeweiligen Schritte aus.

Die regulären Bau-, Quellaudit- und Veröffentlichungsskripte berücksichtigen die neue Auslagerung. Der Veröffentlichungsordner für Band 17 ist `output/04 Zahlen und Folgen/Ergänzungen/Ganze Zahlen/`. Die allgemeine Lesefassung und ihre Beweistabellen verbleiben bei Band 41 unter `output/08 Gruppen/Ergänzungen/Formale Differenzen/`.

## Prüfung

Beide Lesefassungen wurden unabhängig mathematisch gegengelesen. Das Editionsaudit vergleicht alle 94 Tabellenkörper mit dem gesicherten Original und den unten dokumentierten drei Korrekturen. Es prüft außerdem Formeln, Titel, Registerbesitz, die erhaltenen öffentlichen Nummern und Sprungziele, gefilterte Importe sowie lokale und externe PDF-Verweise. Beide Editionsaudits haben bestanden, einschließlich der Navigation von Band 17 zu Band 41 und zurück zu beiden Ganzzahlergänzungen. Die Prüfungen auf undefinierte Verweise, Fehler in den Debug-Protokollen und beschädigten PDF-Text sowie der Quellaudit auf unzulässige Steuerzeichen haben ebenfalls bestanden.

Die neuen Ausgaben wurden vollständig gerendert und visuell geprüft. Seitenumbruchschutz hält Aussagen und Abschnittsüberschriften beim folgenden Inhalt; lange Teilbeweistitel werden von ihren Nummernverweisen getrennt. Diese Prüfungen sichern die Auslagerung und Lesbarkeit. Sie ersetzen keine maschinelle Verifikation der logischen Schlussregeln.

Die ursprüngliche Auslagerung aus Band 41 ist im [zugehörigen Bericht](formale-differenzen-auslagerung-2026-09-21.md) dokumentiert.

## Nachprüfung der für Band 41 benötigten Vorstufen

Beim Ergänzen der Produktbeweistabellen zu Band 41 wurden drei unmittelbar verwendete Herleitungen berichtigt: `IntegerClassInZ`, der Teil `IntegerClassEqualityViaRelation` von `IntegerClassEquality` und `IntegerPairRepresentative`. Die Gleichheitseinsetzungen besitzen nun die erforderlichen Symmetrieschritte. Die beiden Paarzeugen werden getrennt eingeführt; ihre Trägertypen gehen ausdrücklich in die Existenzschlüsse ein, bevor die Zeugen einzeln entladen werden. Aussagen, öffentliche Nummern und Sprungziele bleiben erhalten.

Diese Änderungen wurden unabhängig gegengeprüft. Das ursprüngliche Migrationsmanifest bleibt unverändert. Die drei ursprünglichen und die drei korrigierten Tabellenhashes stehen gesondert in `scripts/integers-proof-corrections-2026-09-21.json`; das Editionsaudit prüft genau diese Fassung sowie die 91 unveränderten Tabellen. Der erneute Bau ergibt 102 Beweisseiten und weiterhin 17 Seiten Lesefassung.

## Gesamtband und Veröffentlichung

Band 17, der Überblick und der Gesamtband wurden neu gebaut. Der Gesamtband umfasst jetzt **2.666 PDF-Seiten**, gegenüber 2.736 Seiten vor der Ganzzahlauslagerung. Das reguläre Bauaudit für Band 17, Band 00 und den Gesamtband hat bestanden. Insbesondere stimmen die Ergebnisregister und Satznummern der Gesamtausgabe mit den Einzelausgaben überein.

Im Gesamtband wurden die vollständigen Ganzzahlseiten PDF 1069–1092 sowie die zugehörige Übersicht auf PDF 74–76 gerendert und visuell geprüft. Der Modellnachweis steht auf PDF 1089, die abschließende Axiomatik auf PDF 1090–1092. Die überprüften Umbrüche und die Unterscheidung zwischen öffentlichen 17- und privaten 17E-Verweisen bleiben erhalten.

Die beiden neuen Ganzzahlergänzungen, die aktualisierte Gruppenlesefassung sowie Band 17, Überblick und Gesamtband wurden in der bestehenden thematischen Struktur unter `output/` veröffentlicht. Die Linkprüfung nach dieser ursprünglichen Auslagerung hat bestanden: **62 PDFs mit 5.642 Seiten, 62.036 lokalen und 39.400 externen Verweisen**. Den anschließenden Stand mit den zusätzlichen Gruppenbeweisen und den drei korrigierten Ganzzahlvorstufen dokumentiert der [Nachtrag zu den Tabellenbeweisen](formale-differenzen-ergaenzende-tabellenbeweise-2026-09-21.md).
