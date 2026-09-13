# Band 08: ausdrückliche Theoremvoraussetzungen

Prüfauftrag vom 7. September 2026: Sachliche Voraussetzungen dürfen in den Theoremen von Band 08 nicht lediglich im Kontext oder in der Begleitprosa stehen. Sie sollen zur Aussage gehören, im Beweis als Annahmen erscheinen und bei späteren Anwendungen ausdrücklich belegt werden.

**Ergebnis:** abgeschlossen. Alle 94 Haupttheoreme und 41 registrierten Hilfssätze wurden geprüft. Die 26 betroffenen Aussagen, ihre Beweise und abhängigen Anwendungen sind korrigiert; weitere entsprechende implizite Voraussetzungen wurden nicht gefunden.

## Umfang und Ergebnis der Aussagenprüfung

Die Prüfung umfasst sämtliche **94 Haupttheoreme und 41 registrierten Hilfssätze** des aktiven Bandes. Davon benötigen **26 Hauptaussagen** ergänzte ausdrückliche Voraussetzungen: elf im Umkehrabschnitt und fünfzehn im Kompositionsabschnitt. Die übrigen Aussagen enthalten die jeweils nötigen sachlichen Voraussetzungen bereits. Die vollständigen Einzelinventare werden mit diesem Bericht archiviert.

Sortenangaben wie „Mengen: A, B“ und syntaktische Abkürzungen für bereits definierte Terme bleiben Kontextangaben. Dagegen gehören Funktionszuordnungen, Bijektivität, Elementzugehörigkeit und die benötigten Kompositionsgleichungen ausdrücklich zur Sequenz. Ein aus einer genannten Bijektivität herleitbarer Funktionstyp wird im Beweis gewonnen; er wird nicht als unnötige weitere unabhängige Voraussetzung eingeführt.

Das beanstandete Theorem **8.3.3.5, Linksumkehrung**, lautet nun:

```tex
F\colon A\bij B\dsep x\in A\vdash F^{-1}(F(x))=x.
```

Der Beweis beginnt mit den beiden nummerierten Annahmen. Er weist die Zielzugehörigkeit von F(x), die eindeutige Urbildexistenz und die Voraussetzungen der angewendeten Injektivität ausdrücklich nach. Die Rechtsumkehrung und die weiteren Umkehrsätze folgen derselben Konvention.

## Geänderte Aussagen

| Bereich | Theoreme | Ergänzungen |
| --- | --- | --- |
| Umkehrfunktion | 8.3.3.1–6, 8.3.3.8–10, 8.3.3.12–13 | Bijektivität; bei Eindeutigkeit zusätzlich Typ und Umkehrbedingung der Vergleichsabbildung; benötigte Elementbedingungen |
| Kompositionen und Inversen | 8.3.4.2–16 | Funktionstypen, Bijektivität bzw. Surjektivität, Typen der Faktoren und beidseitige Umkehrgleichungen |

Die Haupttheoreme werden weder aufgeteilt noch neu angeordnet. Die vollständigen neuen Strukturformeln und stabilen IDs ersetzen die unterprämisierten Referenzschlüssel; es werden keine unvollständigen Altformeln als Kompatibilitätsalias hinzugefügt. Zwölf vorher unbenannte Kompositionssätze erhalten beschreibende Titel. Bestehende Titel bleiben erhalten.

## Beweise und Anwendungen

Die elf betroffenen Umkehrbeweise und sämtliche sechzehn Kompositionsbeweise wurden mit ausdrücklichen Annahmen neu ausgeführt und unabhängig auf Typen, Prämissenreihenfolge, Gleichheitsrichtung und Annahmenentladung geprüft. Beim Satz über die Inverse einer Komposition wird der frühere unpassende Aufruf einer Eindeutigkeitsregel durch eine korrekt typisierte punktweise Herleitung mit anschließendem Extensionalitätsschluss ersetzt.

Fünf spätere Beweise in Band 08 wenden die Linksumkehrung oder Rechtsumkehrung auf ein ausdrücklich angenommenes beliebiges Element an. Erst danach schließen →I und ∀I die universelle Aussage. Alle nachfolgenden Schrittverweise und Abhängigkeiten wurden entsprechend umnummeriert. Weitere konkret gefundene fehlende Typbelege und Beweisargumente werden im ergänzenden Korrekturledger dokumentiert.

Die externe Suche erfasste **109 aktive Quellen** mit ursprünglich **18.789 tatsächlichen Referenzaufrufen**. Die Zuordnung erfolgte mit dem im Projekt verwendeten Lua-Normalisierer und der gesicherten Vorher-Registry. 68 betroffene Originalaufrufe in zehn Dateien werden durch 70 eindeutige ID-Aufrufe ersetzt; zwei bisher gekoppelte Umkehrgleichungen erhalten jeweils zwei Anwendungen und eine Konjunktionseinführung.

Betroffen sind die Bände 09, 10, 11, 20, 21, 28, 37 und 43 sowie die Isomorphiebeispiele von Band 28 und die Darstellung von Band 08 in der Übersicht. Sämtliche 57 ursprünglichen tabellarischen Umkehranwendungen hatten bereits eine tatsächliche Bijektivitätszeile; die Elementbelege wurden an acht Stellen präzisiert. Sieben Kompositionsanwendungen führen die vier einzelnen Voraussetzungen in der richtigen Reihenfolge mit. Die 37 Umkehranwendungen in den beiden B28-Quellen wurden zusätzlich unabhängig geprüft.

Der abschließende Scan einschließlich Band 08 erfasst **110 aktive Quellen mit 19.559 Referenzaufrufen** und findet keinen verbliebenen Aufruf der geänderten alten Theoremziele. Nicht betroffene mathematische Aussagen und ihre Voraussetzungen werden durch diese Migration nicht verändert.

## Gegenprüfung und Satzkorrekturen

Die unabhängigen Prüfungen bestätigen die elf neu ausgeführten Umkehrbeweise mit 81 Zeilen und sämtliche sechzehn Kompositionsbeweise mit 242 Zeilen. Sechs zusätzlich korrigierte frühe Beweise umfassen 70 Zeilen; zwei weitere lokale Gleichheitskorrekturen sind getrennt dokumentiert. Bei den fünf späteren Anwendungen wurden insgesamt zehn nummerierte Zeilen ergänzt, um die jeweiligen Elementannahmen und die anschließende Allquantor-Einführung ausdrücklich auszuführen.

Der erste Build deckte fünf falsche Referenzselektoren auf: Das Injektivitätsaxiom 6.2.1.1 wurde als Theorem gesucht. Die fünf Selektoren sind auf Axiom berichtigt. Eine anschließende unabhängige Prüfung von 200 Referenzaufrufen berücksichtigte ausdrücklich auch die Referenzart und fand keinen Fehler.

Die visuelle Prüfung umfasst die vollständigen geänderten Umkehr- und Kompositionsabschnitte, die korrigierten frühen und späteren Beweise sowie alle 70 externen Anwendungen und Zitate auf 46 Zielseiten. Drei lange Kompositionszeilen erhalten einen Umbruch am Gleichheitszeichen. Lokale Mindestabstände halten die betroffenen Satzköpfe bei ihren Aussagen; die verschobenen Folgeseiten wurden erneut angesehen. Die endgültigen sechs Umkehrseiten sind als Renderbilder identisch mit den bereits visuell geprüften Seiten.

In einer benachbarten B28-Tabelle wurde außerdem eine tatsächliche Kollision in Schritt 54 des Einheitentransports durch einen reinen Formelumbruch behoben. Dieses spätere Layoutdetail ist ausdrücklich vom früheren exakten Verweismigrationsvergleich getrennt dokumentiert. Begründungen, Abhängigkeiten und Referenzargumente bleiben identisch.

## Abschlussprüfung

Die Bände **00, 08, 09, 10, 11, 20, 21, 28, 37 und 43** sowie die Gesamtausgabe wurden neu gebaut. Alle betroffenen Einzelbände bestanden den Referenzaudit. Der abschließende Abgleich bestätigt übereinstimmende Ergebnisnummern in den Einzelbänden und der Gesamtausgabe für **alle 45 Bände**. Die 94 Haupttheoremnummern und 41 Hilfssatznummern von Band 08 bleiben erhalten.

Die bereitgestellte Ausgabe umfasst **46 PDFs mit insgesamt 5019 Seiten**. Sämtliche **58080 lokalen und 33556 bandübergreifenden Links** bestanden die Zielprüfung. Die Gesamtausgabe hat 2496 Seiten, Band 08 hat 85 Seiten. Die veröffentlichten PDFs besitzen dieselben Seitenzahlen und benannten Ziele wie die jeweiligen kompilierten Fassungen.

Die Linksumkehrung steht in Band 08 auf **Druckseite 16 / PDF-Seite 17**, in der Gesamtausgabe auf **Druckseite 592 / PDF-Seite 593**. Auch sämtliche 26 geänderten Aussagen wurden in der finalen Gesamtausgabe visuell gegengeprüft; ihre Voraussetzungen, die korrigierten Kompositionszeilen und die Satzkopfbindungen sind vollständig lesbar.

Die abschließende Layoutdiagnostik und ihre Einordnung sind im PDF-Prüfbericht festgehalten. Der globale Schrittindexscan zeigt dieselben 35 bereits dokumentierten Blindstellen bei Makrofortsetzungen wie zuvor; keine neue Stelle liegt in Band 08 oder den geänderten Anwendungen. Die lokalen Beweisprüfungen erfolgten ergänzend mit den tatsächlichen Annahmenmengen, Regelargumenten und Entladungen.

Der Prüfumfang umfasst die Voraussetzungen sämtlicher Aussagen in Band 08, die zugehörigen Beweisänderungen und ihre abhängigen Anwendungen.

## Nachweise

Die vollständigen Belege liegen unter [assets/b08-explicit-premises-audit-2026-09-07](assets/b08-explicit-premises-audit-2026-09-07/). Dazu gehören:

- [Vollständiges aktuelles Aussageninventar](assets/b08-explicit-premises-audit-2026-09-07/current-source-validation.json) mit allen 94 Haupttheoremen;
- [Anfangs- und Kompositionsprüfung](assets/b08-explicit-premises-audit-2026-09-07/agent01-report.md) sowie [Prüfung des hinteren Bandteils](assets/b08-explicit-premises-audit-2026-09-07/rear-review.md), einschließlich aller 41 registrierten Hilfssätze;
- [Unabhängige Umkehrprüfung](assets/b08-explicit-premises-audit-2026-09-07/inverse-independent-review.md) und [Kompositionsprüfung](assets/b08-explicit-premises-audit-2026-09-07/composition-independent-review.md);
- [Externe Prämissenprüfung](assets/b08-explicit-premises-audit-2026-09-07/external-final-semantic-review.md), Verweismigrationsledger und gesicherte Vorher-Registry;
- [Abschließender Buildnachweis](assets/b08-explicit-premises-audit-2026-09-07/final-build-verification.json), [Zielseiten](assets/b08-explicit-premises-audit-2026-09-07/final-target-pages.json) und [PDF-Schlussprüfung](assets/b08-explicit-premises-audit-2026-09-07/root-main-pdf-qa.md);
- [Gerenderte Linksumkehrung in Band 08](assets/b08-explicit-premises-audit-2026-09-07/linksumkehrung-page-16.png) und [in der Gesamtausgabe](assets/b08-explicit-premises-audit-2026-09-07/main-linksumkehrung-page-592.png);
- [SHA-256-Manifest der archivierten Prüfbelege](assets/b08-explicit-premises-audit-2026-09-07/manifest-sha256.json).
