# Audit der Begründungen in Band 15–27

Geprüft wurden die aktiven LaTeX-Quellen der Bände 15–27 einschließlich der Varianten der `proofstep`-Makros. Ausgangskopien: `b15-b27-before/`. Die Änderungen anderer Arbeiten blieben erhalten; eigene Diffs: `b21-own.diff`, `b27-own.diff`. Band 19 wurde nach der Erstinventur unverändert an `audit_b01_b14` übergeben und wird dort abschließend berichtet.

## Ergebnis

- Band 21: 19 metasprachliche oder unbestimmte Tabellenbegründungen durch konkrete Axiom-, Definitions- und Theoremreferenzen bzw. echte Regelketten ersetzt. Zusätzlich einen ungültigen Versuch der Äquivalenztransitivität und einen nackten Wiederholungsverweis korrigiert. Extensionalität verwendet nun das Mengenextensionalitätsaxiom und `rUI`; die Zweierschicht erhielt einen vollständigen Beweis mit 23 Zeilen, echten Existenz- und Fallentladungen. Die verwendete Termbildmenge hat eine explizite, durch eindeutige Existenz abgesicherte Iota-Definition.
- Band 27: acht Prosa-Begründungen wirklich formalisiert: die Längengleichung beim Schleifenausschluss, drei Schlüsse zu höchstens zwei bzw. null oder zwei Kindern, vier Schlüsse zur geordneten vollen Binärbaumstruktur. Hierfür drei Hilfstheoreme und zwei registrierte Hilfsteilbeweise mit expliziten Fallannahmen, Entladungen, Mengenextensionalität und korrekt gerichteter Gleichheitseinsetzung ergänzt. Im Zeugenargument war außerdem der ursprüngliche Verweis auf Zeile 13 falsch: Verschiedenheit steht in Zeile 14. Die Abhängigkeitsmengen des letzten Teilbeweises sind jetzt explizit.
- Bände 15–18, 20, 22–25: keine entsprechenden aktiven Tabellen-Prosa-Schlussstellen gefunden. Zwei Altbeweise in Band 20 stehen innerhalb `\iffalse` und bleiben unverändert. Bezeichnungs-/Motivationsprosa außerhalb Beweistabellen wird nicht als Beweisregel behandelt.
- Lokale `Abkürzung`- und `Iota-Def.`-Angaben wurden als zulässige explizite Definitionen geprüft und beibehalten. Sie ersetzen keinen Quantoren- oder Fallunterscheidungsschluss.

## Nicht durch bloßes Regelzitat schließbare Konstruktionslücken

Die folgenden sieben Stellen sind absichtlich nicht mit einem nur scheinbar formalen Zitat überdeckt. Sie benötigen eigenständige mathematische Hilfskonstruktionen und Beweise; die vorhandenen Formeln und Begründungen stehen vollständig in `b15-b27-remaining.json`.

- `Bd. 26 - Bäume.tex:2676` — `InternallyDisjointPathsFormCycleCore`: Die Knotenbedingung verweist auf einen davorstehenden Fließtext: geeignete umgekehrte, abgeschnittene und zusammengefügte Wegfolgen samt Disjunktheit und Verschiedenheit müssen formal konstruiert werden.
- `Bd. 26 - Bäume.tex:3391` — `RootPathUniquenessTransfers`: Der erste Kreisabschnitt und ein kürzester Wurzelweg zu dessen Kreisknoten werden nur behauptet. Dafür fehlen die endliche Auswahl und die zwei expliziten einfachen Wurzelwege.
- `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex:9978` — `GoodBinaryAddressSetGraft, Präfixabschluss`: Die Fallzerlegung der Pfropfung in Wurzel und zwei Präfixbilder sowie die jeweiligen Endzerlegungszeugen fehlen.
- `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex:9990` — `GoodBinaryAddressSetGraft, Fülle`: Die Zugehörigkeit beider Kinder muss für Wurzel, linkes und rechtes Präfixbild getrennt hergeleitet und durch Disjunktionselimination zusammengeführt werden.
- `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex:10469` — `GoodBinaryAddressRootPathsUnique, Existenz`: Die Folge aller Anfangswörter ist noch kein konstruierter Funktionsgraph; vollständiger Induktionsbeweis mit Pfadtypisierung fehlt.
- `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex:10486` — `GoodBinaryAddressRootPathsUnique, Eindeutigkeit`: Der erste absteigende Schritt sowie die Gleichheit jedes einfachen Wurzelwegs mit der Anfangswortfolge sind nur textuell argumentiert.
- `Bd. 27 - Endliche Wörter und Klammerungsbäume.tex:10533` — `GoodBinaryAddressChildren`: Die Gleichheit des Elternknotens mit dem um den letzten Buchstaben gekürzten Wort und beide Inklusionen der Kindermenge müssen als Hilfsresultate bewiesen werden.

## Verifikation

- Balanceprüfung aller TeX-Gruppen in den geänderten Dateien erfolgreich, keine neuen Steuerzeichen.
- Neue/ersetzte Theoremreferenzen wurden mit dem echten Lua-Normalisierer gegen die vorhandenen Bandregistries geprüft. Alle auflösbar; die neu eingeführten lokalen IDs werden beim Neubau registriert. Dabei wurde das erforderliche Klammerpaar im Paarmengen-Elementkriterium ergänzt.
- Suche über alle Begründungsvarianten nach nackten Zahlenlisten: ein Fund (Band 21, Wiederholung von Zeile 5) wurde mit `rRE` und dem Identitätstheorem `P→P` ersetzt.
- Die 30 vom vereinfachten Schrittzähler gemeldeten B27-Kandidaten existierten bereits in der Ausgangskopie und entstehen ausschließlich durch nicht expandierte gemeinsame Beweismakros. Die konkreten Makrozeilenzahlen wurden geprüft: `BXXVIIProofLeftFoldCharacterization` 3, `BXXVIIProofTreeNodeConstructorCancellation` 21, `BXXVIIProofTreePositionIota` 2, `BXXVIIProofTreeLeafWordIota` 2, `BXXVIIProofTreeEvaluationIota` 3. Keine neuen Vorwärts- oder Selbstreferenzen durch diese Änderungen.
- Keine Builds oder PDF-Änderungen durch diesen Teilagenten; Buildkoordination beim Hauptagenten.
