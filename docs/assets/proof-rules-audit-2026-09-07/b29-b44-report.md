# Audit Band 29–44: metasprachliche Tabellenbegründungen

Stand: 7. September 2026. Ausschließlich die aktiven Banddateien 29–44 untersucht; Archive/PDFs nicht geändert. Ausgangskopien aller 16 Bände: `b29-b44-before/`. Die bereits vorhandenen Arbeitsänderungen sind erhalten.

## Inventar und Umfang

5.268 ursprüngliche Tabellenzeilen wurden geparst. Eine breite Suche über sämtliche Begründungsfelder ergab 216 Prosa-Kandidaten sowie eine zusätzliche reine Zahlenbegründung, zusammen 217. Vollständige Liste mit unveränderten Originalbegründungen und Ausgangszeilen: `b29-b44-candidate-review.md`, Rohdaten: `b29-b44-candidates.json` und `b29-b44-candidates.txt`.

| Band | Tabellenzeilen ursprünglich | Prosa-Kandidaten |
|---|---:|---:|
| 29 | 39 | 0 |
| 30 | 5 | 0 |
| 31 | 243 | 142 |
| 32 | 3 | 0 |
| 33 | 30 | 0 |
| 34 | 9 | 0 |
| 35 | 33 | 0 |
| 36 | 6 | 0 |
| 37 | 247 | 70 (+ 1 rein numerisch) |
| 38 | 567 | 1 (nur Trennstrich in bestehendem ∃E*-Verweis, kein Fehler) |
| 39 | 355 | 0 |
| 40 | 1.188 | 3 |
| 41 | 125 | 0 |
| 42 | 810 | 0 |
| 43 | 1.608 | 0 |
| 44 | 0 | 0 |

Band 44 hat 44 Fließtextbeweise; Band 37 hat 24, Band 38 und Band 40 haben je drei. Sie wurden als vorhandene Beweisform erfasst, gemäß Abstimmung mit Root vorerst nicht vollständig neu formalisiert. Eine fehlende Prosa-Trefferzahl ist kein maschineller Gültigkeitsbeweis der betreffenden Tabellen.

## Ausgeführte Änderungen

### Band 31

- Transport der ρ-Klassen, ursprüngliche Zeile 918: Schlussäquivalenz nun mit ↔I aus zwei expliziten →I samt den vorhandenen Teilbeweisendpunkten 1–3 und 4–7.
- `FiniteIdempotentSemigroupsGloballyDetermined`, Schlussabschnitt ab Zeile 1452: a und b haben getrennte Trägerannahmen. Die Existenz ihrer Komponenten wird aus der angegebenen McLean-Zerlegung übernommen; Komponentenzeugen stehen in einer eigenen Annahme und werden mit ∃E* eliminiert. Anschließend zwei echte beschränkte ∀I mit korrekter Entladung.
- Existenz des Isomorphismus aus dem konstruierten Kandidaten nun ∃I.
- Abschließender Leer-/Nichtleerfall jetzt ausgeschlossenes Drittes, gesonderte Leerfallannahme, →E und ∨E. Die Nichtleerfallannahme wird dabei ausdrücklich entladen.

### Band 37

- Ursprüngliche Zeile 586: bloße Wiederholungsbegründung `9` durch die in Band 1 definierte Ein-Konjunkt-Kurznotation ∧I* ersetzt; unnötige Zeugenabhängigkeiten dieser Zeile entfernt.
- Ursprünglicher Hilfssatz ab Zeile 2310 vollständig neu formalisiert: 72 Zeilen in drei benannten Hilfsteilen und einem Schluss. Statt unkontrollierter Wahl von a₀, e_l, e_r wird der vorhandene Satz über die Existenz eines Idempotenten verwendet. Die Rechtstranslation wird durch echte Injektivitätsableitung und das Endlichkeitskriterium bijektiv. Ein Idempotentes ist durch beide Kürzungsaxiome neutral. Ein Urbild der Einheit unter der Rechtstranslation liefert ein beidseitiges Inverses. Beide Existenzzeugen werden korrekt eliminiert.
- Eindeutiger neuer Hauptschlüssel `FiniteCancellativeSemigroupGroupExistence` (bewusst verschieden vom vorhandenen B40-Fließtextsatz `FiniteCancellativeSemigroupIsGroup`). Hilfsschlüssel: `FiniteCancellativeRightTranslationBijective`, `CancellativeIdempotentGivesMonoid`, `FiniteCancellativeMonoidIsGroup`.
- Ursprünglicher einseitiger Struktursatz ab Zeile 2429 neu formalisiert: `FiniteOneSidedCancellativeMonogenicGroups` mit Hilfsteilen `MonogenicSubsemigroupIsCommutative` und `CommutativeSubsemigroupOneSidedCancellation`. Die bisher unzulässige unmittelbare Anwendung des Potenzvertauschungssatzes auf die ganze monogene Halbgruppe wurde ersetzt: zwei Potenzzeugen, passende Gleichheitsersetzungen, beide ∃E, dann zwei beschränkte ∀I. Die einseitige Kürzbarkeit wird durch echte ∨E behandelt; anschließend wird der vorhandene Satz über kommutative linkskürzbare Halbgruppen verwendet.
- Literaturfolgern, ursprüngliche Zeile 2654: Äquivalenztransport durch zwei ↔S.
- Literaturfolgern, ursprüngliche Zeile 2663: echte Leer-/Nichtleer-∨E mit zwei Zweigen; Nichtleerheit des zweiten Trägers im zweiten Zweig ausdrücklich aus der vorhandenen Trägeräquivalenz mittels ¬I bewiesen.

### Band 40

`PowerGroupUnitsAreSingletons` ab Zeile 1321: Die pauschale Begründung „Existenzregeln und Konjunktionsregeln“ wurde durch beide Implikationsableitungen mit eigenen Existenzzeugen, ∧E, ∧I, ∃I, ∃E und ↔I ersetzt. Schluss mit zweimal ↔S. `PowerGroupsSingletonLayer`: beide Einheitencharakterisierungen werden nun mit zwei expliziten ↔S auf den Einheitentransportsatz angewandt.

## Verbleibende mathematische bzw. Formalisierungslücken

Die folgenden Stellen wurden ausdrücklich NICHT durch bloß erfundene Regelverweise kaschiert. Die unmittelbaren Regelkorrekturen machen diese Literaturbeweise noch nicht zu vollständig formalen Beweisen.

### Band 31, Voraussetzungen des Satzes `FiniteIdempotentSemigroupsGloballyDetermined`

Die Tabellen vor dem Hauptsatz gehören zu nummerierten Literaturhilfsargumenten (25.6)–(25.35), besitzen größtenteils keine eigenen FormulaThm-Schlüssel und enthalten im Formelfeld teilweise selbst Prosa oder bedingte Sequenzen.

- Zeilen 494–558: Einermengenerkennung in endlichen echten Rechtecksbändern. Die Klassengrößenformel (Zeile 517) benötigt eine konkrete bijektive Kodierung der Teilmengenfamilie und den endlichen Produktsatz; Zeile 524 zusätzlich die strenge Monotonie und beide Projektionsrichtungen. „Je Zeile eine nichtleere Teilmenge wählen“ ist kein direkt ersetzbarer logischer Schluss.
- Zeilen 612–658: Sandwichrechnung. Nach der Existenzaussage werden U₁, U₂, V ohne getrennte Zeugenannahmen weiterverwendet; für die Produktinklusion fehlen Mitgliedschaftsschritte und abschließende ∃E. Auch die umgekehrte Inklusion und Mengengleichheit sind nur skizziert.
- Zeilen 799–1050, insbesondere 836–838, 880–881 und 916–917: Transportlemma. „Wahl von c/s eliminiert“ nennt keine passende Existenzaussage und keinen vollständigen Zeugenunterbeweis. Für s muss z.B. die Nichtleerheit von Ψ(a) importiert werden, die Brückenklasse typisiert und der ρ-Schluss aus der Klasseneigenschaft gewonnen werden. Zeile 959–960 benötigt zusätzlich eine wirkliche Surjektivitätsableitung der Quotientenabbildung. Der neue ↔I-Schluss ersetzt nur die dortige Schließregel; die vorangehenden fachlichen Teilargumente bleiben offen.
- Zeilen 1110–1137: kanonische Hebung. Die aus der Darstellung von u stammenden c,d werden ohne eigene Zeugenannahmen verwendet; Funktionstypisierung und inverse Abbildungen werden lediglich beschrieben. Dafür wären Typisierungs-, Existenz- und Eindeutigkeitsableitungen erforderlich.
- Hauptsatz, Leerfall Zeilen 1241–1261: Die Äquivalenz zwischen leerem Träger und leerer nichtleerer Potenzmenge und der explizite Isomorphismus zwischen zwei leeren Halbgruppen werden nur behauptet. Es fehlen Mengenmitgliedschafts-/Funktions- und Homomorphieableitungen.
- Hauptsatz, Fall 3a, Zeilen 1357–1371: Die Kette vergleicht das Elementprodukt η(a)η(b) unmittelbar mit dem Mengenprodukt Ψ(a)Ψ(C), ferner Ψ(ab) unmittelbar mit η(ab). Hier fehlen Einermengenklammern bzw. die Anwendung der Einermengeninjektivität. Ein Regelname allein würde den Typfehler nicht lösen.
- Hauptsatz, Fälle 2, 3b, 3c und Oppositum: fachliche Folgerungen aus Einermengen, Multiplikativität und Rechts-/Linksnullidentitäten sind teils nur numerisch bzw. durch Fachnamen belegt. In Fall 3c werden Abhängigkeiten von Repräsentanten nicht vollständig dargestellt.
- Neuer Schluss, Zeilen 1470ff: Der Komponenten-/Indexfallensplit und der Rückgriff auf Fälle 1–3d bleiben fachliche Teilbeweisreferenzen, ebenso die Typisierung des komponentenweise konstruierten Isomorphismus. Quantoren- und Existenzschlüsse danach sind jetzt korrekt ausgeschrieben. Eine vollständige Formalisierung muss außerdem die doppelte Verwendung von S/T als Struktur und Trägermenge auflösen.

### Band 37, Literaturfolgern nach den elementaren Sätzen

- Zeilen 2637–2671: Ergebnisse über vollständig reguläre Halbgruppen bleiben als Literaturresultat bezeichnet. Die eingeschobenen Klassen C,D (ursprüngliche Zeilen 2574–2585) werden lediglich als im Rekonstruktionsbeweis auftretend behauptet; ihre Definitionen und ein formaler Übergang zur endlichen Kardinalargumentation fehlen. Diese Aussagen sind nicht aus den angegebenen Prämissen unmittelbar ableitbar.
- Zeilen 2673–2714: Im Fall (3) werden G/S durch Umbenennung bestimmt, e_G aus einem nicht referenzierten Hilfssatz gewählt und F oder F⁻¹ nach dieser Umbenennung verwendet. Für eine vollständige Tabelle braucht es zwei wirkliche Orientierungsfälle und eigene Existenzzeugen/Entladungen. Das einschlägige vorhandene B40-Ergebnis heißt `GroupPowerSemigroupRigidity`; ein bloßer Namensaustausch würde die fehlenden Typisierungen und Zeugenentladungen nicht beheben.
- Zeilen 2717ff: Die Äquivalenzen zwischen leerem Träger und leerer nichtleerer Potenzmenge sowie Leerträgertypisierung sind nur auf Definition/Bijektivität zurückgeführt. Die abschließende logische Leer-/Nichtleerentscheidung ist korrigiert, diese fachlichen Vorstufen noch nicht formal entwickelt.

## Validierung

Alle 16 aktiven Quelldateien besitzen nach den Änderungen balancierte begin/end-Umgebungen. Jeder explizite unterstützte proofstep-Aufruf wurde mit dem klammerbalancierenden Parser aus `scripts/proof-source-audit.py` erfolgreich geparst. Keine neuen Steuerzeichen. Neue Eigenvariablen-/Annahmeentladungen und Schrittverweise wurden lokal geprüft. Neue Schlüssel wurden gegen die übrigen Bände abgeglichen; eine Kollision mit B40 wurde durch den eindeutigen Hauptschlüssel oben beseitigt.

Kein LaTeX-Build und keine PDF-Änderung durch diesen Agenten; Root koordiniert die Builds. Eigene Diffs: `Bd31-changes.diff`, `Bd37-changes.diff`, `Bd40-changes.diff`.
