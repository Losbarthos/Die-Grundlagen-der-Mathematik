# Band 08: visuelle Prüfung der frühen und inneren Beweisänderungen

Geprüfte PDF: `registry/_B08.pdf`, SHA256 `7e1166a68896667abbdd6eec19fa63dcc77a7fd9c6ca6dba6115cd530a4797ff`, 85 physische Seiten. Alle unten genannten Seiten wurden aus dieser Fassung mit Poppler gerendert und tatsächlich als PNG angesehen. Bildpfade und Einzelhashes stehen in `agent01-render-manifest.json`.

| Physische Seiten | Geprüfter Inhalt | Ergebnis |
|---|---|---|
| 5 | Getypter Inj+Sur→Bij-Schluss, 8.2.1.4 | Alle sechs Schritte und quantifizierten Kriterien lesbar. |
| 6–7 | Eindeutige Urbildexistenz, 8.2.1.8 | 15 Schritte einschließlich korrektem Ax.-Selektor, umbrochenem Injektivitätsverweis und ∃!I sauber. |
| 7–8 | Bildgleichheit, 8.2.2.1(H2) | Titel und vollständige Hilfsaussage auf 7, vollständiger 16-zeiliger Beweis auf 8; zulässiger Beweisbeginn auf Folgeseite. |
| 10 | Umgekehrte Identitätsgleichung, 8.3.1.4 | Drei Schritte und beide Schrittargumente sauber. |
| 11 | Identitäts-Bijektivität, 8.3.1.7 | 18 Schritte, zwei getrennte ∀I, Existenzzeuge und Definitionsschluss ohne Kollision. |
| 11–12 | Einschränkung auf ein Urbild, 8.3.2.1 | Sieben Schritte sauber über die Seiten fortgesetzt. |
| 12–13 | 8.3.2.2(H1) und benachbarte Fortsetzungen | Neuer getypter H1 vollständig auf 12; folgende Hilfssätze behalten ihre vollständige Aussage vor dem Beweis-Seitenwechsel. |
| 55–56 | CoreFamilyTransportInjective/Surjective | Neue Elementannahmen, punktweise Umkehrsätze und ∀I sowie Folgeverweise sauber; isolierter H2-Titel zu korrigieren, siehe unten. |
| 65–67 | LayerPowerMapInjective/Surjective und Hauptsatzkontext | Neue Schritte gut lesbar; Haupttitel/Aussage-Trennung zu korrigieren, siehe unten. |
| 70–71 | LayerPowerMapPreservesSubsetsBackward | Neuer ∀I in 17–19, richtig orientierte Gleichheit in 22 und =E in 23 lesbar; Schlussfortsetzung auf 71 sauber. |
| 72 | FixedEmptyBijectionNonemptyPreimageForward | Explizite verschachtelte Symmetrie in Schritt 12 passt mit Zeilenumbruch in die Begründungsspalte; alle 16 Schritte sauber. |

Es wurden 16 Seiten angesehen: 5,6,7,8,10,11,12,13,55,56,65,66,67,70,71,72. In diesen Zielbereichen keine abgeschnittenen Formeln, keine kollidierenden Spalten, keine über den Satzspiegel laufenden neuen Begründungen.

## Zwei lokale Layoutbefunde für den koordinierten Nachbau

1. `CoreFamilyTransportSurjective`, 8.3.6.10(H2): nur der Hilfssatztitel „Surjektivität“ bleibt unten auf physischer Seite 55; die Aussage beginnt erst auf 56. Lokale Bindung des Kopfes an seine Aussage erforderlich.
2. `LayerPowerMapBijective`, 8.3.6.19: Titel und Delta-Kontext stehen unten auf physischer Seite 65; die Aussage folgt erst auf 66. Lokale Bindung des Hauptsatzkopfes an seine Aussage erforderlich.

Beide Punkte wurden Root gemeldet. Keine Quellenänderung und kein Build durch diesen visuellen Review. Vollständige Hilfssatzaussagen vor einem auf der nächsten Seite beginnenden Beweis wurden ausdrücklich als lesbar akzeptiert.

## Abgeschlossener gezielter Vergleich des endgültigen Nachbaus

PDF-SHA256 der zunächst visuell geprüften Kopfkorrektur: `e6ad5a924127c622d207452ad14306dd160cacdb19a14e774a58cdf701702634`. Der Build `build-b08-layout.log` bestätigt das bestandene Verweisaudit. Die Zielseiten wurden aus der aktuellen Registry, AUX und den tatsächlichen PDF-Zielankern erneut bestimmt.

Die physischen Seiten 55, 56, 65 und 66 wurden erneut tatsächlich angesehen. `CoreFamilyTransportSurjective` steht jetzt auf 56 zusammen mit seiner vollständigen Aussage und dem Beweis; auf Vorgängerseite 55 bleibt kein isolierter Kopf zurück. `LayerPowerMapBijective` steht jetzt auf 66 zusammen mit Delta-Kontext, Hauptaussage und Beweisbeginn; auf Vorgängerseite 65 bleibt der vorherige Satz vollständig und ohne isolierten Folgetitel zurück. Alle vier Seiten sind frei von abgeschnittenem Inhalt, Spaltenkollisionen und neuem Randüberlauf. Der folgende H2-Kopf auf Seite 66 behält seine vollständige Aussage auf derselben Seite; der Beweisbeginn auf der Folgeseite entspricht dem akzeptierten Layout.

Beide konkreten Layoutbefunde sind damit erledigt. Aus dieser begrenzten frühen und inneren PDF-Prüfung bleiben keine offenen Layoutpunkte. Die zuvor bestandenen übrigen Zielseiten wurden nach dem rein lokalen Nachbau nicht nochmals flächig geprüft.

## Letzte PDF-Fassung nach den abschließenden Kompositions-Kopfbindungen

Tatsächlich endgültige PDF-SHA256: `29f4d8225e24ac138f7ef8c9ab23416ded96ec762798cbfff720fe35fb03131d`. Aus dieser Fassung wurden die vier physischen Seiten 55, 56, 65 und 66 nochmals mit denselben Poppler-Optionen gerendert. Alle vier PNG-Dateien sind laut SHA256 exakt identisch mit den zuvor tatsächlich visuell geprüften Seiten; auch die Zielanker und Seitenzuordnungen sind unverändert. Daher war keine erneute inhaltliche Bildprüfung erforderlich.

Aktuelles Rendering und PDF-Hash: `final-heads/manifest.json`. Vorheriges Vergleichsmanifest: `final-heads/manifest-before-final-composition-bindings.json`. Vollständiger Hashvergleich: `final-heads/final-comparison.json`; reproduzierbarer Prüfer: `compare-agent01-final-heads.py` im übergeordneten Aufgabenordner. Keine Quellenänderung durch diesen Schlussvergleich.
