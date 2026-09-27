# Inhaltliche Sichtung der Lesefassungen und Vorschlag für das nächste Thema

Stand: 21. September 2026. Grundlage sind die aktuellen LaTeX-Quellen einschließlich des nicht eingecheckten Arbeitsstands. Die frühere Empfehlung zur Klammerungsunabhängigkeit ist inzwischen umgesetzt; sie wird hier als vierte bestehende Lesefassung berücksichtigt.

**Umsetzung:** Die unten empfohlene Lesefassung und der eigenständige Beweisband sind inzwischen angelegt. Aufteilung, Quellen und Prüfungen dokumentiert der [Umsetzungsbericht](formale-differenzen-auslagerung-2026-09-21.md).

Meine Empfehlung lautet **„Wie man Subtraktion möglich macht – von den natürlichen Zahlen zu formalen Differenzen“**. Den anschaulichen Ausgangspunkt liefert Band 17, das allgemeine Ziel der Einbettungssatz für kommutative kürzbare Monoide aus Band 41. Der neue Beweisgedanke ist die Konstruktion einer Struktur durch Äquivalenzklassen und der Nachweis, dass die Rechenoperation von der Wahl der Repräsentanten unabhängig ist.

Geprüft wurden die Argumentationsgänge der vier Lesefassungen und ausgewählte tragende Stellen der möglichen Folgethemen. In den gelesenen Hauptargumenten der Lesefassungen wurde kein konkreter mathematischer Fehler gefunden. Dies ist keine vollständige erneute Prüfung sämtlicher Beweistabellen. Historische Originalquellen, PDF-Layout und PDF-Verknüpfungen wurden nicht unabhängig nachgeprüft.

## Die vier bestehenden Lesefassungen

### Cantor–Schröder–Bernstein

Die Fassung legt das Ziel ihrer Konstruktion früh offen: Eine geeignete Zerlegung erlaubt es, die eine Injektion vorwärts und die andere auf einem passenden Teilbereich rückwärts zu verwenden. Besonders sorgfältig erklärt sind die Schnittkonstruktion, die Fixpunktgleichung aus der Minimalität, die Bilddifferenz unter einer Injektion und das anschließende Zusammenfügen. Die Umkehrfunktion wird erst für die nachweislich bijektive Einschränkung eingeführt. Der Anschluss an die Gleichmächtigkeit macht die spätere Verwendung sichtbar.

Die größte didaktische Ergänzung wäre die Frage, **wie man auf die Hilfsmenge kommt**: Punkte außerhalb von G[B] müssen den F-Zweig benutzen. Gehört ein Punkt zu diesem Zweig, muss auch sein Bild unter G nach F dazugehören, damit es keine Kollision zwischen den Zweigen gibt. Diese Motivation sollte vor der Abschlussbedingung stehen. Sie ergänzt die Erklärung; der vorhandene Beweis benötigt dafür keine Reparatur.

Vorwissen: Mengenoperationen, Bildmengen, Injektionen, Einschränkungen und Umkehrfunktionen. Der historische Schichtenbeweis benötigt zusätzlich natürliche Zahlen und Induktion; das könnte vor diesem Vertiefungsteil kurz ausgewiesen werden.

Fundstellen: [Motivation](../tex/b08/cantor-bernstein/motivation.tex), Zeilen 7–40; [Lesebeweis](../tex/b08/cantor-bernstein/lesebeweis.tex), Zeilen 19–62, 92–150; [Anschluss an Band 11](../tex/b08/cantor-bernstein/b11-anschluss.tex).

### Dedekindscher Rekursionssatz

Der Einstieg mit zwei Zuständen ist besonders wirksam: Er macht das gesuchte Objekt anschaulich und trennt Eindeutigkeit von Injektivität. Danach wird die wirkliche Schwierigkeit ausdrücklich benannt: Eine unter der Rekursionsregel abgeschlossene Relation ist noch kein Funktionsgraph. Die Fixierungsmengen lösen genau dieses Problem. Die Fassung unterscheidet außerdem sauber zwischen einem eindeutigen Wert an jeder Stelle und der Eindeutigkeit der gesamten rekursiv definierten Funktion.

Hier würde ich am Ende eine kurze Anwendung ausführen. Für festes a in den natürlichen Zahlen setzt man den Anfangswert auf a und verwendet den Nachfolger als Übergangsfunktion. Der Rekursionssatz liefert dann F_a(0)=a und F_a(n+1)=Succ(F_a(n)). So wird konkret sichtbar, wie daraus die Definition der Addition entsteht. Der bisherige Schluss kündigt diese Anwendung im Wesentlichen nur an.

Diese Lesefassung ist ein gutes Vorbild für eine neue Konstruktion: wiederkehrendes Beispiel, explizit behandelte Fehlvorstellung, erklärter Beweisplan und ein vollständiges Hauptargument.

Fundstelle: [Lesetext](../tex/b10/dedekind/reading.tex), insbesondere Zeilen 4–30, 71–117, 215–262 und 330–366.

### Mogiljanskaja-Gegenbeispiel

Die Fassung erklärt die mathematische Schwierigkeit überzeugend: Es genügt nicht, zwei Potenzmengen bijektiv aufeinander abzubilden. Die Bijektion muss genau die Informationen bewahren, die das Mengenprodukt verwendet. Die Produktformel, der Ausschluss der Produktrechtecke aus der Reserve und die beiden Zweige der Reservebijektion greifen nachvollziehbar ineinander. Auch der Homomorphiebeweis behandelt beide notwendigen Aussagen: Das Produkt der Bilder stimmt mit dem ursprünglichen Produkt überein, und die Abbildung lässt dieses Produkt selbst fest.

Die größte Hürde ist die hohe Zahl gleichzeitig verwendeter Mengen und Abbildungen. Ich würde vor der Konstruktion vier Aufgaben als kurze Übersicht nennen: Grundhalbgruppen unterscheiden; Produktinformationen bestimmen; Reservebijektion bauen; Multiplikationserhaltung nachweisen. Der lange Abschnitt „Konstruktion und Beweis“ könnte diesen Aufgaben entsprechend untergliedert werden.

Besonders aufschlussreich ist das späte Beispiel, in dem eine dreielementige Teilmenge auf die neue Einermenge {k} abgebildet wird. Eine frühe Vorschau darauf würde die Pointe verständlicher machen. Inhaltlich bleibt dies die anspruchsvollste der vier Lesefassungen; sie setzt sicheren Umgang mit Potenzmengen, Bijektionen und Homomorphismen voraus.

Fundstelle: [Lesetext](../tex/b28/mogiljanskaja/reading.tex), Zeilen 135–223, 263–372, 445–552 und 568–585.

### Klammerungsunabhängigkeit

Der Aufbau ist bereits sehr ausgewogen: fünf Klammerungen bei vier Faktoren; Subtraktion als Gegenbeispiel; Trennung von Faktorenfolge, Baum und Wert; Linksprodukt; Blockgesetz; Bauminduktion; Folgerungen für die Schreibweise. Die Stelle, an der Assoziativität tatsächlich gebraucht wird, wird ausdrücklich erklärt. Ebenso klar ist die Unterscheidung zwischen dem Verketten von Wörtern und dem Verknüpfen ihrer Werte.

Die Anwendung auf Funktionskomposition und die Behandlung von Reihenfolge, Leerprodukt und unendlichen Produkten runden den Text ab. Eine kleine Übersicht „Wort – Baum – Wert“ am Beginn des längeren Begriffsabschnitts wäre ein möglicher Feinschliff. Einen grundlegenden Umbau sehe ich hier nicht als nötig an.

Für die neue Lesefassung würde ich diese frühe Beweisübersicht mit dem wiederkehrenden Beispiel der Dedekind-Fassung verbinden.

Fundstelle: [Lesetext](../tex/b28/bracketing/reading.tex), Zeilen 56–105, 259–325, 343–453 und 461–527.

## Warum formale Differenzen als nächstes Thema?

Die vier vorhandenen Texte behandeln bereits kleinste abgeschlossene Objekte, Rekursion, strukturelle Induktion und eine anspruchsvolle Isomorphiekonstruktion. Die Differenzenkonstruktion ergänzt dies um einen verbreiteten, bisher nicht als Leitgedanken erklärten Beweistyp: Man rechnet mit Darstellungen, fasst gleichwertige Darstellungen zusammen und beweist, dass dadurch eine wohldefinierte neue Struktur entsteht.

Der Einstieg ist vertraut: Die Gleichung x+5=2 hat keine Lösung in den natürlichen Zahlen. Das Ziel ist unmittelbar verständlich: eine Erweiterung, in der solche Gleichungen lösbar werden und die ursprüngliche Addition erhalten bleibt. Das Beispiel bleibt bis zum Schluss verwendbar.

Die benötigte Substanz ist vorhanden. Band 17 konstruiert die ganzen Zahlen aus Differenzenpaaren. Band 41 verallgemeinert diese Konstruktion vollständig bis zur abelschen Gruppe und zur injektiven, operationserhaltenden Einbettung. Eine neue mathematische Hauptkonstruktion ist dafür nicht erforderlich.

Als Vorwissen würde ich natürliche Addition und ihre Rechengesetze sowie Mengen und geordnete Paare voraussetzen. Äquivalenzklassen, Monoid, Gruppe und Einbettung werden jeweils an ihrer ersten Verwendung erklärt. Die vertraute Kenntnis negativer Zahlen kann der Anschauung dienen; sie darf im Konstruktionsbeweis nicht vorausgesetzt werden.

## Vorgeschlagener Aufbau

1. **Eine Gleichung verlangt nach neuen Zahlen.** Mit x+5=2 beginnen. Erläutern, was eine Erweiterung leisten soll: neue Lösungen und Erhalt der bisherigen Rechenregeln. Das allgemeine Ziel früh in Worten nennen: Jedes kommutative kürzbare Monoid lässt sich in eine abelsche Gruppe einbetten.

2. **Differenzen darstellen, ohne schon subtrahieren zu können.** Das Paar (a,b) steht zunächst für eine formale Rechenabsicht. An (2,5) und (3,6) zeigen, warum verschiedene Paare dasselbe neue Objekt darstellen sollen. Definieren: (a,b) ∼ (c,d) genau dann, wenn a+d=b+c. Damit kommt die Definition ausschließlich mit der vorhandenen Addition aus.

3. **Aus Darstellungen werden Äquivalenzklassen.** Reflexivität, Symmetrie und Transitivität begründen. Bei der Transitivität ausdrücklich zeigen, wo gekürzt wird. Danach die Klasse [a,b] als neues Objekt einführen. Eine Gitterzeichnung mit gleichwertigen Paaren auf Diagonalen kann Paar, Klasse und spätere Zahl unterscheiden. Die Beweisübersicht lautet: Gleichheit festlegen → Rechnen auf Klassen ermöglichen → inverse Elemente gewinnen → ursprüngliche Struktur einbetten.

4. **Die entscheidende Probe: Ist das Rechnen wohldefiniert?** Die Regel [a,b] ⊕ [c,d] = [a+c,b+d] motivieren. Dann den vollständigen Beweis führen, dass ein Austausch beider Repräsentanten dieselbe Ergebnisklasse liefert. Die Aussage „Die Formel sieht richtig aus“ ist hier ausdrücklich noch nicht das Argument. An zwei verschiedenen Darstellungen derselben Eingangsklassen die Rechnung wiederholen.

5. **Null, Gegenstücke und die Rechengesetze.** [0,0] als neutrales Element und [b,a] als Gegenstück zu [a,b] nachweisen. Assoziativität und Kommutativität auf die entsprechenden Gesetze der ursprünglichen Addition zurückführen. Die Klassenrechnung zum Anfangsproblem durchführen: [2,5] ⊕ [5,0] = [2,0].

6. **Die alten Zahlen bleiben unterscheidbar.** Die Abbildung n ↦ [n,0] einführen; Additionserhaltung und Injektivität beweisen. Dabei die Unterscheidung aus Band 17 beibehalten: Die ursprünglichen natürlichen Zahlen sind nicht wörtlich Elemente des Quotientenmodells; ihr Bild ist eine kanonische Kopie. Die Klassenrechnung löst damit das ursprüngliche Problem im erweiterten Bereich. Nun wird [2,5] mit der gewohnten negativen Zahl −3 identifiziert und die übliche Schreibweise gerechtfertigt.

7. **Was an der Konstruktion allgemein ist.** Den Beweis auf seine verwendeten Voraussetzungen zurückführen: abgeschlossene, assoziative und kommutative Operation, neutrales Element, Kürzbarkeit. Mit diesen Voraussetzungen dieselbe Konstruktion für ein allgemeines Monoid formulieren und den Einbettungssatz abschließen: Die Zielstruktur ist eine abelsche Gruppe; die Einbettung erhält Operation und neutrales Element und ist injektiv. Die vorherigen Rechnungen müssen nicht nochmals ausgeschrieben werden; der Text muss aber ausdrücklich erklären, weshalb sie für das allgemeine Monoid gelten. Band 41 liefert die zugehörigen vollständigen Ableitungen.

Der Kern soll die additive Konstruktion und ihr allgemeines Prinzip bleiben. Multiplikation, Ordnung und der gesamte weitere Aufbau von Band 17 würden daraus ein wesentlich größeres Vorhaben machen. Eine universelle Eigenschaft der Gruppenvervollständigung wäre ein möglicher späterer Zusatz; sie wird hier nicht als bereits in Band 41 bewiesenes Resultat eingeplant.

## Anbindung an die Skripte

| Aufgabe | Vorhandene Grundlage |
| --- | --- |
| Kreuzsummenrelation ohne vorausgesetzte Subtraktion | [Band 17](<../Bd. 17 - Ganze Zahlen.tex>), Zeilen 66–78; `IntPairRelDef` |
| Äquivalenzrelation und Gleichheit von Klassen | Band 17: `IntegerPairEquivalence`, `IntegerClassEquality`; [Band 41](<../Bd. 41 - Abelsche Gruppen.tex>): `GroupCompletionPairEquivalence`, `GroupCompletionClassEquality` |
| Rolle der Kürzbarkeit | Band 41, Zeilen 309–355 und 2105–2111 |
| Repräsentantenunabhängigkeit | Band 17: `IntegerAdditionCompatible`; Band 41, ab Zeile 817: `GroupCompletionOperationCompatible` |
| Existenz und Eindeutigkeit der Operation auf Klassen | Band 17: `IntegerAdditionQuotientDescent`; Band 41, ab Zeile 873: `GroupCompletionOperationQuotientDescent` |
| Gruppenstruktur und inverse Klassen | Band 41: `GroupCompletionCommutativeMonoid`, `GroupCompletionClassInverse`, `GroupCompletionAbelianGroup` |
| Einbettung und Hauptsatz | Band 41, ab Zeile 1751: `GroupCompletionEmbeddingInjective`; ab Zeile 2049: `GroupCompletionEmbeddingTheorem` |
| Natürliche Zahlen als eingebettete Kopie | Band 17, ab Zeile 618: `NaturalCopyInIntegers` |

Bei einer Umsetzung würde ich die Lesefassung dem Einbettungssatz in Band 41 zuordnen und Band 17 als konkretes Leitbeispiel verknüpfen. Ein Beweisband könnte die allgemeine Kette aus Band 41 in derselben Reihenfolge erschließen. Vor einer tatsächlichen Auslagerung wären die Verwendungen der betroffenen Definitionen und Sätze zu prüfen; die grundlegende Zahlkonstruktion aus Band 17 wird durch diesen Themenvorschlag nicht automatisch ausgelagert.

## Zwei weitere geeignete Kandidaten

**„Wie aus Rechnen eine Ordnung entsteht“**, Band 45: Aus einer assoziativen, kommutativen, idempotenten Operation wird durch x ≤ y genau dann, wenn x ∨ y = y, eine Halbordnung gewonnen. Danach zeigt man, dass die Operation das Paarsupremum liefert, und behandelt die Rückrichtung. Das wäre die kürzere Alternative mit einem klaren Wechsel der Sichtweise. Die Kernabschnitte stehen ab Zeile 439 und 839 in [Band 45](<../Bd. 45 - Halbverbände und Verbände.tex>). Ein Mengenbeispiel mit Vereinigung könnte den gesamten Text tragen.

**„Wie die rationalen Zahlen ihre Lücken schließen“**, Band 19: Dedekindsche Schnitte, rationale Einbettung, Inklusionsordnung und das Supremum als Vereinigung einer nichtleeren nach oben beschränkten Schnittfamilie. Der passende Endpunkt ist die Ordnungsvollständigkeit; die gesamte Körperarithmetik sollte eine eigene Aufgabe bleiben. Grundlage sind die Abschnitte ab Zeile 75 und 982 in [Band 19](<../Bd. 19 - Reelle Zahlen.tex>). Dieses Thema erschließt den analytischen Zweig besonders gut; bei der Umsetzung wären die Voraussetzungen der einzelnen Hilfsaussagen zur Schnittvereinigung nochmals genau abzugleichen.

Für die nächste Lesefassung gebe ich den formalen Differenzen den Vorzug: Das Thema verbindet einen vertrauten Ausgangspunkt, einen durchgehenden Beweis und den für die Reihe neuen Schwerpunkt auf Quotienten und Repräsentantenunabhängigkeit.
