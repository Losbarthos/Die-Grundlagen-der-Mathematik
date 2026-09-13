# Vorschlag für den Ausbau bis zu Gödels Unvollständigkeitssätzen

Die folgenden Bände sind eine Empfehlung. Sie wurden noch nicht als Fachbände
angelegt; sie schließen an die vorhandenen Bände 1 bis 47 an.

Die vorhandene Reihe bringt bereits wesentliche Grundlagen mit: Schlussregeln
und logische Theoreme in den Bänden 1 und 2, Mengen und Funktionen in den
Bänden 3 bis 9, natürliche Zahlen in Band 10, Endlichkeit und Folgen in den
Bänden 20 und 21 sowie endliche Wörter und Klammerungsbäume in Band 27.
Gerade Wörter, Bäume und strukturelle Rekursion eignen sich zur Konstruktion
von Termen, Formeln und endlichen Beweisen.

## Sieben aufeinander aufbauende Bände

| Vorgeschlagener Band | Grundbegriffe beziehungsweise Axiome | Zu entwickelnde Hauptresultate |
| --- | --- | --- |
| **Formale Sprachen und Beweiskalküle** | Signaturen; Terme und Formeln als endliche syntaktische Objekte; freie und gebundene Variablen; kollisionsfreie Substitution; formale Ableitungen im natürlichen Schließen; Theorie und effektive Axiomatisierbarkeit | Eindeutige Lesbarkeit, strukturelle Induktion und Rekursion, Substitutionslemma; präzise Definition von \(T\vdash\varphi\) und syntaktischer Konsistenz |
| **Berechenbarkeit und rekursive Funktionen** | Anfangsfunktionen, Komposition, primitive Rekursion und Minimierung; entscheidbare und rekursiv aufzählbare Mengen | Abschluss- und Kodierungsresultate, eine universelle partielle Berechnungsfunktion, Unentscheidbarkeit des Halteproblems |
| **Robinson-Arithmetik \(Q\)** | Eigene endliche Axiomenliste für \(0,S,+,\cdot\), ohne allgemeines Induktionsschema | Rechnen mit Numeralen, elementare arithmetische Darstellbarkeit; Abgrenzung der im System beweisbaren Aussagen von metatheoretischen Aussagen |
| **Peano-Arithmetik \(PA\)** | Eigene Theorie erster Stufe mit den arithmetischen Grundaxiomen und dem Induktionsschema für jede Formel der Sprache | Formalisierte arithmetische Induktion und die für spätere Kodierungsbeweise benötigten Existenz- und Eindeutigkeitsresultate |
| **Arithmetisierung der Syntax und Repräsentierbarkeit** | Gödelnummern von Wörtern, Termen, Formeln und Beweisen; arithmetische Formeln \(\operatorname{Prf}_T(p,x)\) und \(\operatorname{Prov}_T(x)\); \(\Delta_0\)- und \(\Sigma_1\)-Formeln | Effektivität der Syntaxoperationen, numeralweise Repräsentierbarkeit total berechenbarer Funktionen in \(Q\), \(\Sigma_1\)-Vollständigkeit von \(Q\), arithmetische Darstellung der Beweisprüfung |
| **Diagonalisierung und erster Unvollständigkeitssatz** | Selbstanwendung durch kodierte Substitution; Konsistenz, \(\omega\)-Konsistenz und syntaktische Vollständigkeit | Diagonallemma, Gödels erster Satz mit seinen Voraussetzungen, Rossers Verschärfung; ergänzend Tarskis Undefinierbarkeitssatz |
| **Beweisbarkeit und zweiter Unvollständigkeitssatz** | Standard-Beweisbarkeitsprädikat, formalisierte Konsistenzaussage \(\operatorname{Con}(T)\); Hilbert–Bernays–Löb-Bedingungen | Nachweis der Ableitbarkeitsbedingungen für das gewählte Prädikat, Löbs Satz und Gödels zweiter Unvollständigkeitssatz |

Diese Reihenfolge ist meine Empfehlung für die vorhandene Reihe. Die fachliche
Kette von Rekursionstheorie über Syntaxkodierung zu beiden
Unvollständigkeitssätzen entspricht auch dem Aufbau von Richard Zachs
[Incompleteness and Computability](https://ic.openlogicproject.org/).
Diagonallemma, Repräsentierbarkeit, die Unterscheidung der Konsistenzbegriffe,
Rosser und die Bedingungen an das Beweisbarkeitsprädikat werden auch im
[Oxford-Kurs zu Gödels Unvollständigkeitssätzen](https://courses.maths.ox.ac.uk/course/view.php?id=5613)
ausdrücklich behandelt.

## Axiomatische Trennung

Robinson-Arithmetik und Peano-Arithmetik sollten eigenständige Bände erhalten:
Sie sind verschiedene formale Theorien mit verschiedener Beweisstärke. Der
vorhandene Band über natürliche Zahlen stellt dagegen noch nicht automatisch
die im Unvollständigkeitssatz untersuchte objektsprachliche Theorie \(PA\) dar.
Eine Aussage über die natürlichen Zahlen in der Metatheorie und eine in
\(PA\) kodierte Ableitung müssen ausdrücklich auseinandergehalten werden.

Bei Syntax und Berechenbarkeit werden die Objekte auf den vorhandenen
Grundlagen definiert und konstruiert. Hier sind keine zusätzlichen
Existenzaxiome nötig, wenn sich die Konstruktionen bereits aus den bisherigen
Grundlagen beweisen lassen. Die Unvollständigkeitssätze selbst werden bewiesen;
sie werden nicht als neue Axiome eingeführt.

Für den ersten Satz bietet sich als präzises Ziel Rossers Form an: Jede
konsistente, rekursiv aufzählbar axiomatisierte Erweiterung von \(Q\) ist
syntaktisch unvollständig. Beim zweiten Satz ist ein geeigneter klarer
Ausgangspunkt eine konsistente, rekursiv aufzählbar axiomatisierte Erweiterung
von \(PA\) mit dem üblichen arithmetisierten Beweisbarkeitsprädikat und den
nachgewiesenen Ableitbarkeitsbedingungen: Sie beweist ihre so formulierte
eigene Konsistenz nicht. Diese Voraussetzungen gehören in die Satzformulierung;
die Konsistenz einer Theorie darf nicht mit ihrer Wahrheit oder ihrer
\(\omega\)-Konsistenz gleichgesetzt werden. Gemeint ist dabei
\(\operatorname{Con}(T):=\neg\operatorname{Prov}_T(\ulcorner0=1\urcorner)\).
Zur fachlichen Einordnung siehe die
[Oxford-Lehrveranstaltung](https://courses.maths.ox.ac.uk/course/view.php?id=5613).

Numeralweise Repräsentierbarkeit bedeutet nicht, dass \(Q\) zugleich die
uniforme Totalitätsaussage \(\forall x\,\exists!y\,F(x,y)\) beweist.
Partielle Funktionen und ihre Definitionsbereiche sind gesondert zu behandeln.
Bei der ursprünglichen Gödel-Konstruktion liefert Konsistenz die
Unbeweisbarkeit von \(G_T\), während \(\omega\)-Konsistenz auch die
Unbeweisbarkeit von \(\neg G_T\) sichert. Rosser erreicht beide Richtungen
unter bloßer Konsistenz. Tarskis Satz betrifft die Wahrheit im Standardmodell
\(\mathbb N\), die von der arithmetisch definierbaren Beweisbarkeit zu
unterscheiden ist; siehe den
[ausführlichen Text von Richard Zach](https://ic.openlogicproject.org/ic-print.pdf).

Bei nur aufzählbaren Axiomen muss die Kodierung eines endlichen Beweises auch
die notwendigen Nachweise aus der Axiomenaufzählung enthalten. Eine beliebige
aufzählbare Axiomenmenge hat nicht schon deshalb einen entscheidbaren
Mitgliedschaftstest.

## Sinnvolle Ergänzung

Ein eigener Band **Strukturen, Semantik und Vollständigkeit erster Stufe**
würde das Bild abrunden: Strukturen, Belegungen, Erfüllung, Modelle,
Korrektheit und Vollständigkeit des Kalküls sowie Kompaktheit. Er erklärt
besonders gut, warum die Vollständigkeit der Logik erster Stufe mit der
Unvollständigkeit bestimmter arithmetischer Theorien vereinbar ist.
Für einen rein syntaktischen Weg zu den Unvollständigkeitssätzen muss der
Vollständigkeitssatz nicht als Voraussetzung benutzt werden; didaktisch ist
dieser zusätzliche Band vor der Arithmetisierung dennoch sehr hilfreich.
