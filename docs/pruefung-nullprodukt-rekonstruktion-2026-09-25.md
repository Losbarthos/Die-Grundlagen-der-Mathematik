Prüfung zur Integration des Beweises über Nullproduktprofile

Dieser Bericht dokumentiert die Vorprüfung vor dem anschließenden Umsetzungsauftrag. Den Abschluss der Integration dokumentiert `nullprodukt-integration-pruefung-2026-09-25.md`.

Stand: 25. September 2026. Grundlage ist der aktuelle lokale Arbeitsstand, einschließlich der bereits vorhandenen uncommitteten Änderungen. Das Manuskript wurde für diese Untersuchung nicht geändert; angelegt wurden nur dieser Prüfbericht und die kopierbare Codex-Anfrage.

Quelle: https://chatgpt.com/share/6ab6cc27-72d8-83ed-b081-c0255d3a43fe

Die letzte ausführliche Antwort wurde im Browser gelesen. Die dort verlinkten Anhänge sind nicht Grundlage dieser Prüfung; ihr Dateiinhalt wurde nicht ausgelesen. Die Untersuchung umfasst den im Chat sichtbaren mathematischen Beweis und die relevanten LaTeX-Quellen des Skripts. Sie ist keine vollständige Ableitung im Lemmon-Kalkül und keine maschinelle Beweiszertifizierung.

**Ergebnis**

Der Beweisgang für den angegebenen Spezialfall ist bei direkter und unabhängiger mathematischer Prüfung stimmig: Für endliches S mit Null und S²={0,c}, c≠0, erzwingt P*(S)≅P*(T) die Isomorphie S≅T. Die zusätzliche Endlichkeit von T muss nicht vorausgesetzt werden, wenn sie aus der Endlichkeit von P*(T) und der Singleton-Injektion hergeleitet wird. Weder die allgemeine Potenzhalbgruppenvermutung noch die Erhaltung von Einermengen durch den gegebenen Isomorphismus werden bewiesen.

Der wesentliche Arbeitsaufwand liegt in der vollständigen Formalisierung des Zählarguments, der Quotientenordnung und der faserweisen Bijektion sowie ihrer Einbindung in die Editionsarchitektur. Ein neuer Fachband ist nach dem aktuellen Bestand voraussichtlich nicht erforderlich.

| Baustein | Vorhandener Bestand | Erforderliche Arbeit |
| --- | --- | --- |
| Bijektionen mit vorgeschriebenen Werten | Band 08, TranspositionTermValues, PointedBijectionExists, etwa Zeilen 5170 und 5319 | Zweipunktfall herleiten; besonders zwei ausgezeichnete Elemente im selben Profil |
| Zusammenfügen von Faserbijektionen | Band 09, RetractionFiberBijection, etwa Zeile 965 | Retraktionsvoraussetzungen passen nicht unmittelbar; allgemeines Verklebungslemma oder endliche Variante ergänzen |
| Äquivalenzklassen und Ordnung | Bände 11 und 12 | Präordnung → Äquivalenzquotient → wohldefinierte Halbordnung ergänzen |
| Potenzmengenzählung | Band 20, FiniteNonemptyPowerSetReflectsCardinality, etwa Zeile 5704; ReflectsBijection, etwa Zeile 5790 | Wiederverwenden; keine Logarithmentheorie nötig |
| Endliche Posets | Band 20, FinitePosetMinimalElement, etwa Zeile 6254 | Passendes Argument für Profilfasern aus unteren Mengen, inklusive disjunkter endlicher Zählung |
| Produktquadrate und Isomorphismen | Band 28, Abschnitt ab etwa Zeile 6359, insbesondere SemigroupIsoSquareImage und SemigroupIsoSquareRestriction | Zwei-Produktwert-Lemma ergänzen; vorhandene allgemeine Sätze nutzen |
| Null und Annihilatoren | Band 33, SemigroupZeroUnique sowie Annihilatordefinitionen ab etwa Zeile 181 | Nullproduktprofile und die benötigten Eigenschaften ausarbeiten |
| Hauptaussage | Band 37, Kapitel ab etwa Zeile 2016; Statusabschnitt ab etwa Zeile 2803 | Öffentlicher Hauptsatz mit Einordnung und Links zu beiden Ergänzungen |
| Andere Rekonstruktionssätze | Band 42, Kapitel „Rekonstruktion bei einem Gruppenquadrat“ | Nur thematischer Vergleich; keine Voraussetzung für den neuen Satz |

Zeilenangaben sind Orientierungspunkte des geprüften Stands; bei der Umsetzung die Labels erneut suchen.

**Mathematische Vereinfachungen**

Aus L_p=P*(D_p) und dem Transport der unteren Mengen gewinnt man |D_p|=|D'_{ψ(p)}| direkt mit dem vorhandenen Potenzmengensatz. Die Logarithmen aus dem Chat sind entbehrlich. Ebenso braucht man keine allgemeine Möbiusinversion: Bei einem minimalen Profil mit angeblich abweichender Fasergröße widersprechen die bereits gleichen kleineren Fasergrößen der gleichen Gesamtgröße der unteren Grundelementmenge.

Für den Fall c²=c reicht die direkte Prüfung einer zweielementigen kommutativen idempotenten Halbgruppe. Ihr Produkt uv ist eine Null. Damit sind weder Band 45 noch ein allgemeiner Halbverbandssatz erforderlich. Eine Null von T² wird über 0t=(00)t=0(0t)=0 und das duale Argument zur Null von T; allgemeine Idealtheorie ist ebenfalls verzichtbar.

**Stellen, die in der Formalisierung ausdrücklich abgesichert werden müssen**

- P*(S) enthält nur nichtleere Mengen; die leere Menge darf die Nulltests nicht verfälschen.
- Der Profilquotient ist zunächst eine geordnete Menge. Eine multiplikative Kongruenz wurde nicht vorausgesetzt oder nachgewiesen.
- Manche Profile enthalten keine Einermengen. Die Singleton-Profilabbildung ist deshalb nicht automatisch surjektiv.
- |C_p| zählt Grundelemente, nicht die Anzahl beliebiger Teilmengen im Profil p.
- P*(U)²=P*(U²) gilt hier wegen der zwei Produktwerte; dies ist kein voraussetzungsloser allgemeiner Satz.
- Ein Nullelement der Potenzhalbgruppe allein darf nicht ohne Argument zur Null der Grundhalbgruppe erklärt werden. Der Beweis verwendet zusätzlich die Struktur des zweielementigen Produktquadrats.
- Die Potenzhalbgruppe eines beliebigen Halbverbands muss nicht idempotent sein. Der benötigte spezielle Dreielementträger wird direkt geprüft.
- Das Zusammenfügen der Bijektionen und die Fixierung von 0 und c sind echte Existenzbeweise, einschließlich des Falls eines gemeinsamen Profils.
- Das Beispiel mit drei Produktwerten zeigt nur die Grenze der Nullproduktinformation; seine Potenzhalbgruppen sind wegen unterschiedlicher Kommutativität selbst nicht isomorph.

**Empfohlene Editionsform**

Das Muster des Mogiljanskaja-Gegenbeispiels passt am besten: Hauptsatz und kurze Bedeutung im Fach- und Gesamtband, wiederverwendbare Grundlagen in früheren Bänden, spezielle Hilfsresultate und Tabellen in einer Ergänzung mit eigenem Nummernraum, vollständige erklärende Lesefassung daneben. Als Arbeitsname bietet sich „Nullprodukt-Rekonstruktion“ zu Band 37 an. Technische Vorlagen liegen in `tex/b28/mogiljanskaja/` und `tex/b40/reconstruction/`; die zweite Vorlage ist kein mathematischer Abhängigkeitsvorschlag.

Betroffen sind neben den mathematischen Quellen die Einstiegspunkte unter `editions/`, Editionsmakros, Registries, Build- und Publikationsskripte, Verzeichnisse, Überblicksband und die PDF-Verlinkung. Vorhandene Nummern und Verweisziele sollten erhalten bleiben. Die neue Beweistabellenfassung darf die Hauptaussage nicht konkurrierend neu registrieren.

**Quellen- und Prüfumfang**

Das bestehende Skript dokumentiert bereits, dass erfolgreiche Builds und Referenzprüfungen keine mathematischen Beweise verifizieren. Dieser Unterschied muss bei der Umsetzung erhalten bleiben. Die im Chat erwähnte Kontrolle von 727 Tabellen wurde hier nicht reproduziert. Ein eigenständiger Literatur- oder Neuheitsnachweis des Spezialfalls wurde nicht erbracht.

Tamuras Abstract von 1987 wurde zusätzlich an der Primärquelle geprüft: https://link.springer.com/chapter/10.1007/978-94-009-3839-7_22. Dort wird das allgemeine Resultat ausdrücklich ohne Beweis berichtet; dieser Beitrag ersetzt den erforderlichen Beweis nicht. Für die benachbarte Gruppenrekonstruktion wurde außerdem der Abstract von Liu–Tringali geprüft: https://arxiv.org/abs/2606.01917. Er betrifft Gruppen und liefert keinen Ersatz für den hier zu integrierenden Nullproduktbeweis.

Die unmittelbar verwendbare Umsetzungsanfrage steht in `docs/codex-anfrage-nullprodukt-rekonstruktion-2026-09-25.md`. Sie wurde auf Wunsch auf Ziel, mathematischen Umfang und wesentliche Qualitätsanforderungen gekürzt. Die konkrete Beweisarchitektur und Umsetzung bleiben Codex überlassen; dieser Prüfbericht dient bei Bedarf als Hintergrund.
