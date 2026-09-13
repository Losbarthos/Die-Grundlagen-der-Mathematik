# Belege zur erneuten Prüfung der Schlusslisten

Die Inventare erfassen die sichtbaren Aussagen vollständig, einschließlich registrierter Hilfssätze. Bei Makros mit getrenntem Strukturargument wird nur die Anzeige auf Lesbarkeit geprüft; die ältere Referenzformel ist kein sichtbarer Rückfall in die Kommadarstellung.

- `b01-b14-inventory.json`, `b01-b14-review.json` und `b01-b14-active-coverage.json`: vollständiges Inventar, Einzelentscheidungen und aktiver Registerabgleich; deaktivierte Deklarationen separat markiert.
- `b15-b27-inventory.json`, `b15-b27-verification.json` und `b15-b27-report.md`: vollständige Deckung und die zwei vor der Korrektur gefundenen B21-Kandidaten.
- `b00-b28-inventory.json` und `b00-b28-reviewed.json`: Überblick und Band 28 einschließlich aktiver Isomorphiesammlung; vor der Korrektur erfasste Anzeigen mit abschließender Einordnung.
- `b29-b44-reviewed.json` und `b29-b44-report.md`: vollständige Anzeigen und Einzelentscheidungen im restlichen Bereich.
- `b21-list-changes.json`, `b21-list-changes.diff`, `b21-list-verification.json` und `b21-list-implementation.md`: tatsächliche B21-Änderungen und unabhängiger Erhaltungsnachweis.
- `b28-two-displays-independent-review.json` und `.md`: tatsächliche B28-Änderungen und unabhängiger Vergleich sämtlicher unveränderter Quellbereiche und Beweiszeilen.
- `final-source-check.json` und `.md`: abschließender unabhängiger Abgleich aller vier Korrekturen, der beiden vom Nutzer genannten Beispiele und der globalen Deckung.
- `standalone-build-verification.json` und `final-build-verification.json`: Register-/Nummernvergleich, Dateihashes und exakte Seiten der fertigen Ausgaben.
- `standalone-visual-review.json`, `main-visual-review.json` und `published-render-verification.json`: Sichtprüfung aller acht betroffenen Seiten und pixelgleicher Rendervergleich der veröffentlichten PDFs.
- `publication-link-audit.json`: erfolgreicher Abschluss des Builds und vollständige Linkprüfung aller 46 veröffentlichten PDFs.

Die Bereichsberichte unterscheiden den lesenden Erstbefund von den anschließend umgesetzten Korrekturen. Maßgeblich für die fertige Ausgabe sind zusätzlich das abschließende Quellen- und Build-Ergebnis sowie die dokumentierte PDF-Sichtprüfung.
