# Erneute Prüfung der Schlusslisten – 7. September 2026

Der erneut gemeldete Satz **28.2.15.2 – Elementare Rechenzugriffe auf einen Isomorphismus** war zu Beginn dieser Prüfung bereits korrekt gesetzt: sechs eigene Zeilen `(i)` bis `(vi)` mit einmal vorangestellten gemeinsamen Prämissen. Dies wurde im veröffentlichten Band-28-PDF auf Druckseite 120 geprüft. Das Vorbild **27.2.3.4 – Typisierung des verschobenen Konkatenationsblocks** verwendet ebenfalls römische Teilnummern; seine unterschiedlichen Prämissen stehen jeweils beim zugehörigen Punkt.

## Vier zusätzliche Korrekturen

| Band / Satz | Aussage | Neue Teilnummern |
| --- | --- | ---: |
| 21.5.5.1 | Lineare Grenzwertregeln | 3 |
| 21.6.2.2(H2) | Typisierung und Verschiedenheit der Marker | 2 |
| 28.2.15.22(H1) | Globale Multiplikationsbedingungen | 2 |
| 28.2.15.24(H1) | Kriterium für das Relationsbild | 2 |

Die vier Stellen enthalten jetzt insgesamt neun einzeln nummerierte Folgerungen. Wo Voraussetzungen vorhanden sind und für alle Folgerungen gelten, stehen sie gemeinsam vor der Aufzählung. Bei den Markern werden die gemeinsame Typisierung und die Verschiedenheitskonjunktion getrennt aufgeführt; die Variablenliste innerhalb der Typisierung bleibt zusammen.

Geändert wurden ausschließlich die sichtbaren Aussagen in `Bd. 21 - Folgen.tex` und `tex/B28-isomorphism-examples.tex`. Die vorherigen Strukturargumente, IDs, Titel und Delta-Kontexte bleiben exakt erhalten. Der Grenzwertsatz verwendet dazu das vorhandene Makro `FormulaThmDeltaKR`; die drei Hilfssätze verwenden bereits ein getrenntes Anzeige- und Strukturargument. Alle Beweise sind unverändert. Der unabhängige Quellenvergleich bestätigt, dass außerhalb dieser vier Anzeigen beziehungsweise der notwendigen Makroumstellung keine Änderung vorgenommen wurde.

## Vollständige Deckung

Die erneute Inventur umfasst alle aktiven Aussagenanzeigen in den Bänden 00 bis 44, einschließlich der aktiven Isomorphiesammlung von Band 28 und der registrierten Hilfssätze:

| Bereich | Haupttheoreme | Registrierte Hilfssätze |
| --- | ---: | ---: |
| 00 einschließlich Überblicksdateien | 0 | 0 |
| 01–14 | 1.350 | 273 |
| 15–27 | 613 | 435 |
| 28 einschließlich Isomorphiesammlung | 175 | 116 |
| 29–44 | 455 | 105 |
| **Gesamt** | **2.593** | **929** |

Die aktiven Haupttheoremzahlen wurden mit den fertigen Registern abgeglichen. 154 deaktivierte Deklarationen in expliziten `\iffalse`-Blöcken sind separat erfasst: 117 in Band 10 und 37 in Band 20. Die frühere Zahl von 2.708 Theoremdeklarationen zählte die 115 darin enthaltenen deaktivierten Haupttheoreme mit; sie ist deshalb von der hier ausgewiesenen aktiven Deckung zu unterscheiden.

Geprüft wurden die sichtbaren Anzeigen, nicht die absichtlich bewahrten alten Strukturformeln. Die Suche berücksichtigte Kommas, `\dsep`, Zeilenumbrüche und größere Abstände. Bestehende Teilnummerierungen wurden ebenfalls gelesen. Prämissenlisten, gebundene Variablen, Tupel, gemeinsame Existenzmatrizen, Gleichheitsketten, ergänzende Abbildungsdefinitionen und ausdrücklich konjunktive Einzelkonklusionen wurden nicht irrtümlich als unabhängige Schlusslisten aufgeteilt. Über die vier korrigierten Fundstellen hinaus ergab die Prüfung keine weitere entsprechende Schlussliste.

## Prüfung der Ausgabe

Band 21, Band 28, der Überblick und der Gesamtband wurden erfolgreich neu gebaut. Die vier geänderten Stellen wurden jeweils im Einzelband und im Gesamtband visuell geprüft. Zusätzlich wurden alle acht entsprechenden Seiten aus den veröffentlichten PDFs gerendert: Sie sind pixelgleich zu den bereits geprüften Seiten. Keine Formel ist abgeschnitten; die Teilnummern und gemeinsamen Prämissen sind vollständig sichtbar.

| Stelle | Druckseite im Einzelband | Druckseite im Gesamtband |
| --- | ---: | ---: |
| 21.5.5.1 | 42 | 1465 |
| 21.6.2.2(H2) | 61 | 1484 |
| 28.2.15.22(H1) | 176 | 1929 |
| 28.2.15.24(H1) | 187 | 1940 |

Die Satznummern und Ergebnisregister aller 45 Einzelbände stimmen mit dem Gesamtband überein. Auch gegenüber der vorherigen Ausgabe sind sämtliche Labelnummern erhalten. Die vorhandenen Überbreitenwarnungen haben unveränderte Häufigkeiten und Breiten; neue kamen nicht hinzu. Die vollständige Linkprüfung der 46 veröffentlichten PDFs bestand mit 5.019 Seiten, 58.080 lokalen und 33.556 bandübergreifenden Links. Band 21 hat 75 PDF-Seiten, Band 28 hat 255 und der Gesamtband 2.496.

Die [Prüfbelege](assets/theorem-conclusion-lists-audit-2026-09-07/README.md) enthalten die vollständigen Inventare, Einzelentscheidungen, aktive Deckung, Vorher-/Nachher-Anzeigen und unabhängigen Quellvergleiche. Der dort separat vermerkte doppelte Ableitungsstrich bei `MinimalSeparatorDecomposition` in Band 42 ist keine Schlussliste und wurde in dieser Darstellungsänderung nicht bearbeitet.
