# PDF-Kontrolle B28: 16 nummerierte Beispiel-Familien

Abgeschlossen am 7. September 2026 nach dem letzten gezielten B28-Nachbau mit H-Kennzeichnung. `tmp/theorem-numbering/rebuild-B28-last.log` bestätigt `Reference audit passed: B28`. Letzte PDF-Datei: `registry/_B28.pdf`, 2.716.711 Bytes, SHA256 `830a7318e68708da4f0d3d2db952a3d842e5aab4dcbf9fbe5aa5d62e2356b08c`, Dateizeit 16:34:13.

Alle 16 Familien aus `tex/B28-isomorphism-examples.tex` wurden nach dem Build mit `locate-families.py B28 --render` lokalisiert und als PNG visuell geprüft. Die 56 Aussagen tragen vollständig die erwarteten römischen Kennzeichnungen. Die Voraussetzungen und Fortsetzungszeilen bleiben lesbar; keine Anzeige ragt sichtbar über den Satzspiegel. Alle Haupttheoremüberschriften stehen zusammen mit ihrer Variablenliste und Anzeige. Sichtbare H-Kennzeichnungen sind von den römischen Aussagekennzeichnungen eindeutig unterscheidbar.

| Schlüssel | Theorem | PDF-Seite / gedruckte Seite | Aussagen | Anzeige |
|---|---|---|---:|---|
| `SemigroupIsoElementaryTransport` | 28.2.15.2 | 121 / 120 | 6 | geprüft |
| `SemigroupIsoSubstructureTransport` | 28.2.15.3 | 124 / 123 | 4 | geprüft |
| `SemigroupCarrierPowersCalculus` | 28.2.15.6 | 134 / 133 | 3 | geprüft |
| `SemigroupIsoPositiveCarrierPowers` | 28.2.15.7 | 137 / 136 | 2 | geprüft |
| `SemigroupIsoGeneratedSubsemigroups` | 28.2.15.8 | 139 / 138 | 4 | geprüft |
| `SemigroupIsoPrincipalIdealsAndGreen` | 28.2.15.10 | 143 / 142 | 3 | geprüft |
| `SemigroupIsoDirectProducts` | 28.2.15.14 | 153 / 152 | 3 | geprüft |
| `SemigroupCanonicalProductIsomorphisms` | 28.2.15.18 | 165 / 164 | 5 | geprüft |
| `SemigroupIsoCentralizers` | 28.2.15.20 | 171 / 170 | 4 | geprüft |
| `SemigroupIsoLocalCarriers` | 28.2.15.21 | 173 / 172 | 3 | geprüft |
| `SemigroupIsoIdentitiesZerosUnits` | 28.2.15.22 | 177 / 176 | 3 | geprüft |
| `SemigroupIsoFreshAdjunctions` | 28.2.15.23 | 184 / 183 | 5 | geprüft |
| `SemigroupIsoCongruenceQuotients` | 28.2.15.24 | 187 / 186 | 2 | geprüft |
| `SemigroupIsoEndomorphismConjugation` | 28.2.15.26 | 199 / 198 | 2 | geprüft |
| `SemigroupIsoSubstructureOrders` | 28.2.15.27 | 207 / 206 | 4 | geprüft |
| `SemigroupIsoEquationSolutionTransport` | 28.2.15.28 | 215 / 214 | 3 | geprüft |

## Historische Umbruchbefunde aus der ersten Sichtprüfung, inzwischen behoben

Im ersten Gesamtbuild standen die folgenden Hilfsteilüberschriften allein am Ende der genannten Seite, während ihre Formel auf die Folgeseite fiel:

| PDF-Seite | Hilfsteil | Überschrift |
|---:|---|---|
| 121 | 28.2.15.2(H1) | Quellhalbgruppe |
| 153 | 28.2.15.14(H1) | Koordinatenabbildung |
| 214 | 28.2.15.28(H1) | Auswertungen liegen im Träger |

Zusätzlich endete PDF-Seite 165 mit der einfachen Beweiszwischenüberschrift „Umklammerung:“. Diese Befunde wurden an die koordinierende Instanz gemeldet und anschließend lokal korrigiert. Die ursprüngliche vollständige Anzeigenprüfung und die nachfolgenden gezielten Sichtprüfungen sind abgeschlossen; es gibt daraus keinen verbleibenden Layoutbefund.

Die Bilder liegen als `B28-final-<PDF-Seite>.png` neben diesem Bericht. `B28-final-pages.json` enthält die über Registry und PDF-Sprungziele ermittelte Zuordnung aller 29 B28-Familien; die 13 Familien aus der Hauptdatei prüft unabhängig der Agent für Band 29 bis 44.

## Lokale Korrektur nach der Sichtprüfung

Auf Auftrag der koordinierenden Instanz wurde ausschließlich `\RequirePackage{needspace}` in `tex/impl/proof-tables.tex` ergänzt. In der Beispieldatei stehen jetzt lokale `\Needspace`-Reservierungen vor den drei betroffenen Beweisanfängen (8, 12 bzw. 8 Grundlinien) und vor „Umklammerung“ (5 Grundlinien). Die Reservierungen umfassen Überschrift, angezeigte Formel und ersten Beweisschritt; vor den drei ersten Hilfsteilen wird auch „Beweis.“ mitgebunden. Die Ausgangskopien liegen unter `tmp/theorem-numbering/b28-head-bindings-before/`. Eine erneute globale Gestaltung der Hilfsteile wurde nicht vorgenommen.

Die erste gezielte Nachprüfung bestätigte alle vier Kopfbindungen: Quellhalbgruppe auf PDF 122, Koordinatenabbildung auf PDF 154, Umklammerung auf PDF 166 und Auswertungen auf PDF 215. Danach wurden zwei weitere konkrete lokale Layoutpunkte behoben: Der Hilfsteiltitel 28.2.15.7(H1) lautet kürzer „Abschluss der Produktpotenzen“; vor Definition 28.2.15.6 reservieren 20 Grundlinien Platz für Überschrift, Delta-Liste und die vollständige Formel. Anzeigen, Referenzschlüssel, H-Zähler und Beweisschritte blieben bei diesen lokalen Layoutänderungen unverändert.

## Letzte gezielte Sichtprüfung

Nach dem letzten B28-Nachbau wurden die zwei letzten Korrekturen und der möglicherweise verschobene Auswertungs-Hilfsteil neu lokalisiert, gerendert und geprüft:

| PDF-Seite | Stelle | Ergebnis |
|---:|---|---|
| 137 | 28.2.15.7(H1), `SemigroupIsoPositivePowersCarriers` | Ausreichender Abstand zwischen verkürztem Titel und H1-Referenz. |
| 154 | Definition 28.2.15.6, `SemigroupCoordinateProductMapsDef` | Überschrift, Delta-Liste und vollständige fünfzeilige Formel stehen gemeinsam auf der Seite. |
| 154 | 28.2.15.14(H1), `SemigroupCoordinateProductForwardFacts` | Kopf, dreizeilige Formel und erste Schritte bleiben zusammen. |
| 215 | 28.2.15.28(H1), `SemigroupTermEvaluationCarrier` | Hauptfamilie, Beweisanfang, H1-Formel und Schritte stehen sauber zusammen. |

Die obige Seitenzuordnung aller 16 Familien wurde nach diesem letzten Nachbau über Registry, Aux-Datei und PDF-Sprungziele aktualisiert. Dieser letzte Durchlauf war eine gezielte Nachprüfung der geänderten Stellen; die vollständige Sichtprüfung aller Familienanzeigen erfolgte zuvor. Der Quellenabgleich aller 58 geänderten Familien blieb nach den letzten Änderungen fehlerfrei.

`b28-last-layout-pages.json` enthält die letzten vier Zielpunkte und den PDF-Hash. Die frischen Bilder heißen `B28-last-layout-137.png`, `B28-last-layout-154.png` und `B28-last-layout-215.png` unter `tmp/theorem-numbering/pdf-qa/`. Die dauerhafte Berichtskopie sichert diese Beobachtungen und die maschinenlesbaren Seitenzuordnungen; große PDF-Dateien und PNGs werden nicht mitgesichert. Diese Layoutprüfung ist keine mathematische Verifikation der Beweise.
