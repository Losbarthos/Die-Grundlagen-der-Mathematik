# Schlusskontrolle der nummerierten Familien in B21 und B26

Stand: 2026-09-07, nach dem gezielten B21-Nachbau um 16:24 Uhr. Die vom Root koordinierten PDFs aus dem abschließenden Vollbuild wurden nach dem jeweiligen Eintrag `Reference audit passed` geprüft. Beide enthalten die zentralen Änderungen der Theorem- und Hilfsteilnummerierung. B21 enthält zusätzlich die später ergänzte Definition `FormulaDefDeltaKR`; diese neue Makrodefinition verändert keine vorhandenen Makros und wird in B26 nicht verwendet. Es wurden keine eigenen LaTeX-Builds gestartet.

## B26: abgeschlossen

Alle vier Familien wurden als PNG gerendert und vollständig visuell gelesen:

| ID | PDF-Seite | Ergebnis |
| --- | ---: | --- |
| ForestAccess | 45 | Zwei Aussagen vollständig, Überschrift und Kontext zusammen |
| TreeAccess | 50 | Drei Aussagen vollständig, Überschrift und Kontext zusammen |
| TreeParentAccess | 60 | Drei Aussagen vollständig, Überschrift und Kontext zusammen |
| OrderedFullBinaryTreeAccess | 74 | Zwei Aussagen vollständig, Überschrift und Kontext zusammen |

Keine abgeschnittenen Zeichen, Überlagerungen oder getrennten Theoremüberschriften. Die sichtbaren römischen Aussagekennzeichen und die H-Kennzeichnung benachbarter registrierter Hilfsteile sind unterscheidbar.

## B21: abgeschlossen

Alle zwölf Hauptaussagefamilien sind vollständig und sauber gesetzt. Geprüfte PDF-Seiten: 8, 16, 18, 41, 60, 64, 65, 68, 69, 71, 73, 75. Die vollständige Zuordnung der IDs, Titel und Aussagezahlen steht in `b21-final-pdf-qa-pages.json`.

Ein benachbarter langer Hilfstitel auf PDF-Seite 60 berührte den neuen H1-Verweis. Der Titel wurde von „Die ersten beiden Zeilen liegen außerhalb der Reserve“ zu „Die ersten beiden Zeilen liegen außerhalb von \(U\)“ gekürzt. Formeln, Schlüssel, ID, Zähler und Referenzziele bleiben unverändert. Die Einzeländerung steht in `b21-qa-title-fix.json`.

Auf PDF-Seite 69 wurde bei der im früheren Beweisaudit ergänzten Definition `B21ShiftImageTermSetDef` eine überbreite Delta-Zeile festgestellt. Die eindeutige Existenz und die Definition selbst werden nun zweizeilig gesetzt. Der echte Lua-Normalisierer erhält Layouttoken wie `begin{aligned}`, `&` und Zeilenumbrüche im Strukturkey. Deshalb verwendet die Anzeige das neu ergänzte `FormulaDefDeltaKR` mit exakt erhaltener Original-Strukturformel und derselben ID. Bestehende Makros sind unverändert. Nachweise: `b21-definition-layout-keycheck.lua`, `verify-b21-definition-layout.py` und `b21-definition-layout-verification.json`.

Der gezielte B21-Nachbau hat die Referenzprüfung bestanden (`rebuild-B21-final.log`). Alle zwölf Zielseiten wurden erneut ermittelt und gerendert; ihre Seitenpositionen sind unverändert. Die geänderten PDF-Seiten 60 und 69 wurden erneut vollständig visuell geprüft: Hilfstitel und H1-Verweis besitzen nun klaren Abstand; Definition, Delta-Kontext und Referenz passen vollständig in die Satzbreite. Die nummerierte Hauptaussage darunter bleibt sauber. Auch die Registry bestätigt weiterhin Nummer 21.6.4.2, ID `B21ShiftImageTermSetDef` und Strukturkey `am551345a60be1fb48cf206db56429cde2`. Damit sind alle hier erfassten Layoutbefunde abschließend behoben und geprüft.

## Belege und Grenzen

`prepare-b21-b26-pdf-qa.py` verwendet `pdftotext -layout` zur eindeutigen Seitenermittlung und `pdftoppm` zur vollständigen Seitenansicht. Die Bilddateien heißen `b21-final-page-*.png` und `b26-final-page-*.png`. Die Kontrolle ergänzt die Referenzaudits; sie ist keine neue Behauptung, die im Beweisaudit dokumentierten mathematischen Konstruktionslücken in B26/B27 seien geschlossen.
