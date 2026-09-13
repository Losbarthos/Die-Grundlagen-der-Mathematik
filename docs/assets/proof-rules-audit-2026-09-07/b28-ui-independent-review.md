# Unabhängige Prüfung der 56 All-Einführungsschlüsse in Band 28

Grundlage: `b28-stage1-ui.json` und der aktuelle Text von `tex/B28-isomorphism-examples.tex` nach den beiden weiteren Umnummerierungsstufen. Keine Änderungen an der geprüften Datei.

Alle 56 Ledger-Ziele wiedergefunden und anhand der aktuellen Beweisschritte geprüft. Die beiden identischen Matrizen der linken und rechten Ideale (Ausgangszeilen 729, 743) wurden separat berücksichtigt. Zusätzliche identische Annahmen und bereits vorher formale Umkehridentitäten sind keine weiteren Ledger-Ziele.

Geprüft wurden:

- Reihenfolge der einzeln gebundenen Variablen gegenüber der verschachtelten `∀I`-Reihenfolge;
- beschränkte Quantoren und die jeweils vorgeschaltete `→I`-Entladung;
- getrennte Implikationsannahmen bei Relationen, Kongruenzen und Induktionsschritten;
- Matrixformel des verwendeten Endschritts;
- verbleibende Abhängigkeitsindizes und Zuordnung der neu eingeführten `A`-Zeilen;
- Erhaltung der ursprünglichen Annahmengruppen durch `∧I*`.

Die Quantorenreihenfolge und Entladungen sind in allen 56 Zielschlüssen richtig. In zwei Fällen weicht aber die referenzierte Matrix von der zu quantifizierenden Endrelation ab:

1. `SemigroupCarrierPowersSubsemigroups`, Teil **Absteigende Folge und Unterhalbgruppen**, Prüfstand Zeile 583, Schritt 10: der verwendete Schritt 9 enthält `A^{n+2}=A^{n+1}A⊆A^nA=A^{n+1}`, Zielmatrix ist nur `A^{n+2}⊆A^{n+1}`. Vor der Quantifizierung ist die Endrelation aus den Gleichheiten und der Inklusion durch Gleichheitselimination zu gewinnen.
2. Derselbe Teil, Prüfstand Zeile 591, Schritt 18: der verwendete Schritt 17 enthält `A^{n+k+1}⊆A^{n+k}⊆A^n`, Zielmatrix ist nur `A^{n+k+1}⊆A^n`. Der vorhandene Teilmengentransitivitätssatz liefert die benötigte Matrix.

Beide Befunde wurden Root mit den aktuellen Schrittnummern gemeldet. Der nicht vorhandene beschreibende Schlüssel in der ersten Nachricht wurde sofort auf den tatsächlichen Schlüssel `SemigroupCarrierPowersSubsemigroups` berichtigt.

Die Prüfung bestätigt nur die neu eingesetzten Quantoren-/Implikationsschlüsse. Weitere Metaprosa in den jeweils verwendeten vorgelagerten Matrixableitungen wird damit nicht als mathematisch bewiesen bewertet.
