# Halbverbände und Ordnung: Lesefassung und Beweistabellen

Stand: 22. September 2026.

Umgesetzt wurde die Empfehlung aus der [inhaltlichen Prüfung der bestehenden Lesefassungen](lesefassungen-pruefung-und-themenvorschlag-2026-09-22.md): **„Wie aus einer Rechenregel eine Ordnung wird – Halbverbände zwischen Algebra und Ordnung“**, als Ergänzung zu Band 45.

## Die beiden Ausgaben

- [Lesefassung](../output/05%20Ordnungen%20und%20Verbände/Ergänzungen/Halbverbände%20und%20Ordnung/Bd.%2045%20-%20Halbverbände%20und%20Ordnung%20-%20Lesefassung.pdf): 11 PDF-Seiten einschließlich Titelblatt.
- [Beweistabellen](../output/05%20Ordnungen%20und%20Verbände/Ergänzungen/Halbverbände%20und%20Ordnung/Bd.%2045%20-%20Halbverbände%20und%20Ordnung%20-%20Beweistabellen.pdf): 19 PDF-Seiten einschließlich Titelblatt, mit 23 ausgelagerten Tabellen.

Die Lesefassung führt alle wesentlichen Argumente aus. Ihre Verweise auf Band 45 und die Beweistabellen dienen der Zuordnung und Vertiefung. Zwei Zeichnungen verbinden die Vereinigungstafel mit dem Hasse-Diagramm und zeigen die beiden wechselseitigen Konstruktionen.

## Aufbau der Lesefassung

1. **Ein durchgehendes Beispiel:** Auf der Potenzmenge einer zweielementigen Menge wird aus der Vereinigungstafel die Inklusionsordnung abgelesen.
2. **Drei Rechengesetze:** Assoziativität, Kommutativität und Idempotenz werden motiviert und von zusätzlichen Eigenschaften abgegrenzt.
3. **Von der Operation zur Ordnung:** Die Beziehung `x ≤ y ⇔ x ∨ y = y` wird auf Reflexivität, Antisymmetrie und Transitivität geprüft.
4. **Die universelle Eigenschaft:** `x ∨ y` ist die kleinste gemeinsame obere Schranke von `x` und `y`. Supremum, Minimum und Maximum werden unterschieden.
5. **Von der Ordnung zur Operation:** Eindeutige Paarsuprema liefern einen Funktionsgraphen. Die Konstruktion benötigt keine willkürliche Auswahl.
6. **Die Rückrichtung beweisen:** Idempotenz und Kommutativität folgen aus der Supremumseigenschaft. Assoziativität wird über die kleinste obere Schranke dreier Elemente bewiesen, ohne das gesuchte Rechengesetz vorauszusetzen.
7. **Beide Rückgewinnungen und die Grenzen:** Die Ausgangsoperation beziehungsweise Ausgangsordnung wird exakt zurückgewonnen. Der Schluss erklärt endliche nichtleere Suprema, die zusätzliche Rolle eines kleinsten Elements, fehlende unendliche Suprema und die duale Sicht mit Infima.

## Welche Tabellen ausgelagert wurden

| Teil | Kennungen | Anzahl |
| --- | --- | ---: |
| Träger, Auswertung und induzierte Ordnung | `JoinOrderFirstCarrier`, `JoinOrderSecondCarrier`, `JoinOrderEvaluation`, `JoinOrderReflexive`, `JoinOrderTransitive`, `JoinOrderAntisymmetric`, `JoinSemilatticeInducesOrder` | 7 |
| Die Operation als Paarsupremum | `JoinUpperLeft`, `JoinUpperRight`, `JoinLeastUpper`, `JoinIsPairSupremum` | 4 |
| Von Paarsuprema zur Halbverbandsoperation und zurück zur Ordnung | `PairJoinUpperLeft`, `PairJoinUpperRight`, `PairJoinLeastUpper`, `PairJoinIdempotent`, `PairJoinCommutative`, `PairJoinAssociative`, `PairJoinCharacterization`, `PairJoinRecoversOrder` | 8 |
| Das Vereinigungsbeispiel | `PowerSetUnionClosure`, `PowerSetUnionSemilattice`, `SubsetIffUnionEqualsRight`, `PowerSetUnionOrderIsInclusion` | 4 |
| **Gesamt** | **19 Kerntabellen und 4 Beispieltabellen** | **23** |

Die Aussagen bleiben an ihren bisherigen Stellen in Band 45. Jede erhält dort einen direkten Link zur zugehörigen Tabelle. Insbesondere bleiben die zentralen Sätze 45.2.3.7, 45.2.3.12, 45.2.4.7 und 45.2.4.8 unter ihren bisherigen Nummern zitierbar.

## Quellen und technische Umsetzung

- [Gemeinsame Aussagen](../tex/b45/semilattice/statements.tex): die 23 ursprünglichen Deklarationen, jeweils einmal gespeichert.
- [Lesetext](../tex/b45/semilattice/reading.tex) und [Zeichnungen](../tex/b45/semilattice/reading-diagrams.tex).
- [Beweistabellen](../tex/b45/semilattice/proofs.tex) und [Darstellung der zugehörigen Aussagen](../tex/b45/semilattice/proof-display.tex).
- [Lesefassungsdatei](../editions/b45-semilattice-reading.tex) und [Beweisbanddatei](../editions/b45-semilattice-proofs.tex).
- [Build-Skript](../scripts/build-semilattice-editions.ps1), [Prüfskript](../scripts/semilattice-editions.py) und [Vergleichsbestand](../scripts/semilattice-manifest.json).

Band 45 registriert die gemeinsamen Deklarationen weiterhin kanonisch. Der Beweisband zeigt dieselben Aussagen an, ohne sie ein zweites Mal zu registrieren. Beide Ergänzungen importieren die Register von Band 45 und seinen Voraussetzungen; ihre eigenen Satzregister bleiben leer. Damit entstehen weder neue Satznummern noch konkurrierende Ziele für bestehende Verweise.

Der Vergleichsbestand hält die ursprünglichen Aussagen und Tabellen sowie alle 147 kanonischen Kennungen und die zugehörigen AUX-Ziele von Band 45 fest. Der Quellenvergleich ignoriert ausschließlich Unterschiede im Leerraum. Die zusätzlichen Umbruchregeln liegen außerhalb der ursprünglichen Aussage- und Tabellenkörper.

Vollständiger Neubau einschließlich Einordnung, Gesamtband, Prüfungen und Veröffentlichung:

```powershell
./scripts/build-semilattice-editions.ps1
```

Nur die Ergänzungen neu bauen, wenn die kanonischen Bände bereits aktuell sind:

```powershell
./scripts/build-semilattice-editions.ps1 -EditionsOnly
```

Die Ergänzungen sind auch in den Gesamtbuild und die PDF-Veröffentlichung aufgenommen. README, Bandverzeichnis, Build-Dokumentation und der Überblick zu Band 45 nennen die neuen Ausgaben.

## Prüfung

Die Lesefassung wurde auf einen vollständigen und nicht zirkulären Argumentationsgang gelesen. Eine zusätzliche unabhängige Inhaltsprüfung des vollständigen Lesetexts und beider Diagramme fand keine mathematischen oder erheblichen didaktischen Fehler; geprüft wurden insbesondere Voraussetzungen, umgekehrte Konstruktion, Assoziativität, beide Rückgewinnungen und die Aussagen zu Suprema. Die Originalaussagen und Originaltabellen wurden automatisch mit dem festgehaltenen Ausgangsstand verglichen. Dies ist eine Prüfung von Inhalt, Quellentreue und Verweisen; eine maschinelle Verifikation sämtlicher mathematischer Beweisschritte wird damit nicht behauptet.

Prüfergebnisse:

- Alle 23 Aussagekörper und alle 23 Tabellenkörper stimmen mit dem Ausgangsstand überein.
- Alle 147 kanonischen Kennungen, Satznummern und benannten PDF-Ziele von Band 45 bleiben erhalten.
- Beide Ergänzungen haben leere eigene Satzregister. Ihre kanonischen Verweise und sämtliche internen und externen PDF-Verweise bestehen den Audit.
- Band 45 enthält alle 23 direkten Verweise zu den ausgelagerten Tabellen. Seine Ausgabe umfasst jetzt 57 statt 64 PDF-Seiten.
- Der aktualisierte Überblick umfasst 113 PDF-Seiten. Seine 1.239 externen Verweise sowie die 452 externen Verweise von Band 45 bestehen den Zielabgleich.
- Alle Seiten der beiden neuen Ergänzungen wurden gerendert und visuell geprüft, ebenso die betroffenen Aussagen in Band 45 und die ergänzte Überblicksseite. Die beiden Ergänzungen haben keine übervollen oder untervollen Textboxen und keine undefinierten Verweise im Build-Log.
- Das erweiterte Quelleninventar erfasst die ausgelagerten Tabellen und meldet keine ungültigen Steuerzeichen.
- Die veröffentlichten Ergänzungen haben identische Seiteninhalte wie die visuell geprüften Build-PDFs. Ihre Veröffentlichung ändert nur die Dateipfade der Querverweise.
- Der Gesamtband wurde vollständig neu gebaut und umfasst 2.659 PDF-Seiten. Der Abgleich sämtlicher Ergebnisregister und AUX-Satznummern zwischen Gesamtband und Einzelausgaben ist bestanden. Auch seine 189 externen Verweise auf 137 unterschiedliche Ziele sind gültig.
- Die betroffenen Aussagen, Verweise und die ergänzte Überblicksseite wurden zusätzlich im Gesamtband visuell geprüft.
- Die abschließende Veröffentlichungsprüfung besteht für die gesamte Sammlung: **64 PDFs, 5.740 Seiten, 62.024 interne und 41.231 externe Verweise**.

Die beiden neuen Ergänzungen, Band 45, der Überblick und der Gesamtband sind im regulären Ausgabeordner aktualisiert. Die bisherigen Aussagen, Kennungen und Satznummern von Band 45 bleiben erhalten.
