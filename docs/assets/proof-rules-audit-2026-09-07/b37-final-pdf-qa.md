# Abschließende PDF-Kontrolle der B37-Verweisreparatur

Prüfer: `audit_b15_b27`, 2026-09-07. Geprüft wurde `registry/_B37.pdf` aus dem bestandenen Standalonebuild vom selben Tag, 16:28 Uhr. Die Standorte wurden anhand von Registry und AUX bestimmt, die betreffenden vollständigen PDF-Seiten mit Poppler gerendert und visuell gelesen.

Ergebnis: Alle acht Prüfziele sind vollständig und sauber dargestellt.

| Prüfziel | PDF-Seite | Ergebnis |
| --- | ---: | --- |
| Definition `FiniteSemigroupMonoidConventionDef`, Def.37.5.5.1 | 42 | Titel, Delta-Kontext und vollständiges Definiens innerhalb der Satzbreite |
| Definition `FiniteSemigroupGroupConventionDef`, Def.37.5.5.2 | 42 | Titel, Delta-Kontext und vollständiges Definiens innerhalb der Satzbreite |
| `CancellativeIdempotentGivesMonoid`, Schritt18 | 44 | Vollständiger Definitionsverweis mit verschachtelter ∧I-Kette |
| `FiniteCancellativeMonoidIsGroup`, Schritt4 | 44 | Vollständige ∧E-Kette |
| Derselbe Hilfsteil, Schritt16 | 44 | Vollständige ∧E-/∀E-/→E-Kette, sauber über mehrere Zeilen verteilt |
| Derselbe Hilfsteil, Schritt17 | 44 | Vollständige ∧E-/∀E-/→E-Kette, sauber über mehrere Zeilen verteilt |
| Derselbe Hilfsteil, Schritt24 | 45 | Vollständiger Definitionsverweis mit ∧I |
| Abschließender Existenzteil, Schritt8 | 45 | Vollständige ∧E-Kette |

Bei der verkleinerten Ganzseitenansicht auf PDF-Seite43 wurde zunächst ein zu geringer Abstand zwischen dem Hilfstitel „Ein Idempotentes ist beidseitig neutral“ und dem H2-Verweis vermutet. Ein hochauflösender Ausschnitt und die Textpositionen zeigen rund91pt freien Abstand: kein Layoutfehler. Der Originaltitel ist unverändert im Schlussstand enthalten; es gibt hierzu keinen offenen Befund und keine abschließende Layoutkorrektur.

Nach Rücknahme einer zwischenzeitlichen optionalen Titelkürzung wurde der Quellenstand gegen die zum bestandenen Build gehörende Datei `registry/_B37.fdb_latexmk` geprüft. Der mit LF-Zeilenenden berechnete MD5 lautet `0a3f2a7f84b114b5c2b11cd30292d8b5` und stimmt mit dem gespeicherten latexmk-Quellhash überein. Auch die tatsächliche Dateigröße von142093Bytes stimmt. Der rohe Datei-MD5 ist bei gemischten Windows-Zeilenenden nicht derselbe Vergleichswert. Eine separate unmittelbare Vollkopie vor der vorübergehenden Titeländerung lag nicht vor; behauptet wird daher dieser erfolgreiche Buildhash-Abgleich, keine gesondert nachgewiesene Bytegleichheit mit einer solchen Kopie.

Bildbelege: `final-pdf-page-42.png` bis `final-pdf-page-45.png`; Detailansicht `title-crop.png`. Der maschinenlesbare Hashbeleg steht in `title-reversion-verification.json`. Es wurde kein eigener Build gestartet und keine allgemeine weitere B37-Prüfung vorgenommen.
