# Unabhängige Prüfung der B28-Anwendungen der Umkehrsätze

Ergebnis: **bestanden, keine Belegkorrektur erforderlich**. Geprüft wurde der von Agent29 freigegebene Quellenstand nach der externen B08-Verweismigration. Keine TeX-Änderungen und keine Builds durch diese Prüfung.

Die aktuelle Quelle enthält 37 Anwendungen der elf migrierten Inverse-IDs: zwei im Hauptband und 35 in `tex/B28-isomorphism-examples.tex`. Die 35 Anwendungen stehen in 33 Beweiszeilen; zwei Zeilen enthalten jeweils zwei punktweise Anwendungen mit anschließender Konjunktionseinführung.

## Semantische Befunde

- In allen 37 Anwendungen ist das erste Argument eine vorherige Zeile mit einer ausdrücklichen Bijektivität der tatsächlich benötigten Abbildung. Kein Aufruf benutzt dafür lediglich eine Isomorphieaussage oder einen Funktionstyp.
- Die Bijektivitätszeilen werden aus dem Isomorphieaxiom gewonnen; bei den beiden Koordinatenanwendungen wird die ausdrücklich vorausgesetzte Familie von Bijektionen mit dem jeweiligen Indexmitglied spezialisiert.
- Die zwei Hauptbandaufrufe verwenden die bewiesene Bijektivität von `eta_B : B bij Sing(B)` in Zeile 16. Die Anwendung der Rechtsinverse verwendet zusätzlich das bewiesene `F({a}) in Sing(B)` in Zeile 27. Die zweite Anwendung ist Bestandteil der bereits vorhandenen Gleichheitskette.
- Alle zusätzlichen Elementvoraussetzungen stimmen mit der jeweiligen Definitions- beziehungsweise Zielmenge überein. Die sechs einzelnen Anwendungen auf zusammengefasste Mitgliedschaften benutzen die passende Konjunktionselimination. Bei den beiden Doppelanwendungen werden beide Mitgliedschaften getrennt eliminiert und anschließend die beiden Gleichungen zusammengeführt.
- Die beiden Eindeutigkeitsanwendungen in den Teilen zur Konjugation und zu Kongruenzen verwenden korrekt `h : B bij A`, `f : A -> B` und die zuvor bewiesene Aussage `forall x in A, h(f(x))=x`. Die Reihenfolge entspricht `InverseFunctionRightInverseUniqueness` nach der Instanziierung mit `F=h` und `G=f`.
- Die Abkürzung `h=f^{-1}` ist im Abschnitt ausdrücklich festgelegt; die Anwendungen benötigen dafür keine weitere sachliche Voraussetzung.

## Prüfbeleg

`review-b28-inverse-applications.py` liest die beiden aktuellen Quellen unabhängig vom Migrationsledger, rekonstruiert die Beweiszeilenzähler einschließlich expliziter Fortsetzungen und erfasst jeden Aufruf samt tatsächlich zitierter Prämissenformel. Das Ergebnis liegt in `b28-inverse-application-review.json` mit Dateihashes, Quellzeilen, Ziel-IDs und vollständigen Belegformeln. Die semantische Prüfung ergänzte diese strukturelle Bestandsaufnahme; sie ist kein allgemeiner neuer Review aller umgebenden B28-Beweise.
