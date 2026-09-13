# Layout-Audit B20–B27

Alle acht Bände wurden anhand abgeschlossener serieller Buildlogs geprüft; PDF-Stichproben kontrollieren die tatsächlichen Formeln und Begründungen. Keine eigenen Kompilationen in dieser Runde. Root führt den abschließenden seriellen Gesamtlauf nach der zentralen Änderung der Spaltenbreiten aus. Schrittnummern, Abhängigkeiten, Gründe und Theoremschlüssel wurden bei den Formelumbrüchen bewahrt.

| Band | Prüfung / Änderung | Verifikation |
| --- | --- | --- |
| B20 | Eine Begründungsüberbreite von 38,9 pt: die drei Quellen beim binären Teilmengencode auf drei Zeilen aufgeteilt. | PDF-Seite 72 bestätigt Ursache. Nachlauf ohne Tabellenüberbreiten; sechs verbleibende Warnungen betreffen Überschriften und frühere Aussage-Displays. |
| B21 | Acht reine Begründungsüberbreiten von 0,5–65,1 pt: Umbruchstellen zwischen unabhängigen Referenzen und Textteilen ergänzt. | PDF-Seiten 64/72 geprüft; Nachlauf ohne Overfull. Seite 64 nach Korrektur sauber. |
| B22 | Zwei Formeln um 1,6/2,2 pt zu breit: Umbruch nach dem Existenzquantorenblock ergänzt. | PDF-Seite 20 vorher/nachher geprüft. Nachlauf ohne Overfull. |
| B23 | Keine Änderung erforderlich. | Finaler Log ohne Overfull; PDF-Seite 8 sauber. |
| B24 | Keine Änderung erforderlich. | Finaler Log ohne Overfull; PDF-Seite 5 sauber. |
| B25 | Keine Änderung erforderlich. | Finaler Log ohne Overfull; PDF-Seite 5 sauber. |
| B26 | 24 verklebte TeX-Befehle in eingefügten Formeln repariert. Neun Tabellenstellen umbrochen bzw. eine nicht umbrechende innere makecell-Hülle entfernt; acht lange Aussage-Displays einschließlich der 1273-pt-Zykluskernformel vollständig strukturiert. | Erfolgreicher Nachlauf: alle acht Anzeigeformeln und sechs der neun Tabellenstellen ohne Überbreite. Die drei Reststellen hatten einen leeren &-Präfix vor dem eigentlichen &, der eine zusätzliche Ausrichtungsspalte erzeugte. Diese Präfixe nach PDF-Kontrolle auf Seite 17 entfernt; identische vierte Formel mit Quantor war bereits sauber. Abschließender Nachlauf durch Root steht noch aus. |
| B27 | Alle 13 Begründungs-parboxen nutzen die volle bereits eingeschränkte Zellbreite; innere nicht umbrechende makecell-Hüllen entfernt. Neun Zeilenformeln und drei Anzeigeformeln umbrochen. | Vollständiger Vorlauf ausgewertet; PDF-Seiten 128/131 bestätigen Formel-/Grundkollisionen. Tokenvergleich aller zwölf Formelargumente nach Entfernung reiner Layoutbefehle bestanden; alle 2581 Zeilenkommandos, Abhängigkeiten und Gründe bewahrt. Abschließender Nachlauf durch Root steht noch aus. |

B26: Die acht Anzeigeformeln betreffen `FinitePathTailSegment`, `FinitePathFreshEndpointExtension`, `FinitePathTransportPropertyDef`, `FinitePathReversalPropertyDef`, `FinitePathFinalSegment`, `FinitePathSplitRigidity`, `FinitePathInteriorPairReduction` und `InternallyDisjointPathsFormCycleCore`. Beim letzten Satz wird die bereits im Beweis verwendete Knotenmenge U ausdrücklich als Abkürzung aufgeführt; die expandierte Knoteneigenschaft verwendet frische gebundene Variablen. Das beseitigt zugleich die Variableinfang-Falle der vorherigen direkten Makroexpansion.

B27: Die 31 identischen Überbreiten von 3,90042 pt sind ausschließlich dreistellige Schrittnummern ab 100. Root hat dafür zentral die Nummernspalte von .03 auf .04 linewidth und die Abhängigkeitsspalte von .10 auf .09 linewidth geändert. Positionen und Breiten der Formel- und Begründungsspalten bleiben gleich. Diese Korrektur wird beim abschließenden Gesamtlauf geprüft.

Alle Quellen B20–B27 sind für Root freigegeben. Nachlaufreste oder neue Fehler erfordern gegebenenfalls eine weitere gezielte Runde; zum Zeitpunkt dieses Berichts wurde keine ungeprüfte Kompilation als bestanden bezeichnet.

Bildbelege: `tmp/pdfs/B20-B27-layout/`.

Einzelprotokolle: `tmp/proof-audit/B21-reason-layout-edits.json`, `B26-glued-command-fixes.json`, `B26-final-layout-rows.json`, `B26-display-layout-keys.json`, `B27-paragraph-reason-layout-edits.json` und `B27-final-formula-layout-edits.json`.
