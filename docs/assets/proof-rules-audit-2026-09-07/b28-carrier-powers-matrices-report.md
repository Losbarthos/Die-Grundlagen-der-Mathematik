# Matrixkorrekturen: SemigroupCarrierPowersSubsemigroups

Geändert wurde ausschließlich der Beweisteil **Absteigende Folge und Unterhalbgruppen** in `tex/B28-isomorphism-examples.tex`. Die Theorem-Anzeigen einschließlich sämtlicher FormulaThmDeltaKR-Argumente sowie der Kopf/Schlüssel dieses Hilfsteils bleiben unverändert. Vor dem Schreiben wurde der aktuelle Dateistand erneut gelesen und nur der unverändert vorgefundene eigene Beweisblock ersetzt.

## Korrekturen

- Alte Zeile 9 wurde in vier Zeilen aufgelöst. Neue Zeilen 9 und 11 geben die benötigten, über den Gleichheitssymmetriesatz orientierten Definitionsgleichungen an; Zeile 10 enthält die bisher in der gemischten Kette enthaltene Produktinklusion. Zeile 12 gewinnt daraus exakt `A^{n+2}⊆A^{n+1}` durch `=E(9,11,10)`. Die folgende All-Einführung in Zeile 13 verweist nun auf diese Matrix.
- Alte Zeile 17 wurde in zwei Zeilen aufgelöst. Neue Zeile 20 enthält den ersten Teil der bisherigen Inklusionskette; Zeile 21 gewinnt `A^{n+k+1}⊆A^n` mit dem in Band 3 bewiesenen Transitivitätssatz aus 20 und der Induktionsannahme 18. Die folgende All-Einführung in Zeile 22 verweist auf diese exakte Matrix.
- In derselben Tabelle wurde bei Zeile 5 zusätzlich die Richtung der verwendeten Gleichheit korrigiert: Für das Ersetzen von A durch A^1 muss aus `A^1=A` zunächst `A=A^1` gewonnen werden. Der Gleichheitssymmetriesatz steht nun explizit vor `=E`.

Die bisherigen vorgelagerten Produktzeugen-/Instantiierungsbegründungen wurden inhaltlich erhalten. Dieser eng begrenzte Nachtrag ist keine vollständige Formalisierung aller übrigen Begründungen dieses Hilfsteils.

## Umnummerierung und Validierung

`tmp/metaproof-audit/edit_rows.py` remappte alle folgenden Schritt- und Abhängigkeitsindizes innerhalb dieses Hilfsteils: 25 → 29 Schritte. Die Originalformeln/Strukturkeys wurden nicht der Indexersetzung unterzogen.

- Alle 29 Zeilen lassen sich mit dem Beweistabellenparser lesen.
- Alle formalen numerischen Begründungsverweise zeigen ausschließlich auf vorangehende Zeilen.
- Alle angegebenen Abhängigkeiten beziehen sich auf bereits eingeführte Annahmen.
- Die beiden Endmatrizen und die beiden folgenden verschachtelten `∀I`/`→I`-Begründungen wurden exakt geprüft.
- Beim Schreiben wurde verifiziert, dass Präfix und Suffix außerhalb des betroffenen Beweisblocks unverändert bleiben.
- Kein Build gestartet; keine PDFs geändert.

## Sicherungen und Nachweise

- `b28-carrier-powers-matrices-before.tex`: vollständiger Ausgangsstand beim Arbeitsbeginn.
- `b28-carrier-powers-matrices-before-block.tex` / `-after-block.tex`: exakter eigener Block vorher/nachher.
- `b28-carrier-powers-matrices-changes.diff`: eigener Blockdiff.
- `b28-carrier-powers-matrices-ledger.json`: die drei ersetzten Ausgangsschritte.
- `b28-carrier-powers-matrices-validation.json`: geprüfte Abhängigkeiten und formale Zeilenverweise.
