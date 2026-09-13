# Audit der Beweisgliederung B22–B44 (ohne B28)

Stand: 6. September 2026. Vollständige Inventur aller 22 zugewiesenen aktiven Banddateien; 638 explizite Beweisumgebungen mit 8.728 vorhandenen `proofstep`-Aufrufen. Geprüft wurden sämtliche Aussagen und Gliederungsstrukturen, nicht nur Stichproben. Dieser Audit betrifft die redaktionelle Trennung selbständiger Beweisziele; er ersetzt keine vollständige formale Verifikation aller mathematischen Argumente.

52 Tabellenbeweise wurden mit bestehenden unregistrierten `proofpart`/`proofpartwide`-Bausteinen gegliedert. Die Schrittzahlen laufen über `setcounter{proofstepnr}` weiter; vorhandene Abhängigkeiten und Referenzen bleiben damit stabil. 27 Fließtextbeweise erhielten benannte Teile. Registrierte Proofparts, Theoremformeln, Schlüssel und Labels wurden nicht verändert.

## Vollständige Bandinventur

| Band | Beweise | Bereits gegliedert | Jetzt bearbeitet | Begründete Ausnahmen / Ergebnis |
|---|---:|---:|---:|---|
| B22 | 18 | 8 | 1 | Unmittelbare Endpunkttypisierungen und die Bündelung bereits bewiesener Nachbarschaftskriterien bleiben zusammen. |
| B23 | 7 | 1 | 0 | Die einzige selbständige Äquivalenzargumentation war bereits geteilt; die übrigen Beweise gewinnen jeweils eine Eigenschaft. |
| B24 | 4 | 0 | 0 | Strukturzugriff und Einführungskriterium verwenden kurze Axiomenketten; der induzierte Teilgraph übernimmt die bereits bewiesene ungerichtete Struktur. |
| B25 | 2 | 0 | 0 | Zwei kurze Strukturzugriffe; die Konjunktion wird unmittelbar aus der Graphenhierarchie gewonnen. |
| B26 | 64 | 8 | 10 | Kurze Typisierungsbündel und existenzquantifizierte Zeugen mit zusammengehörigen Daten werden nicht künstlich auf mehrere Existenzaussagen verteilt. |
| B27 | 76 | 41 | 3 | 41 bereits gegliederte Beweise einschließlich der langen Wort-/Baumrekursionen beibehalten; kurze Anwendungen der Rekursionssätze bleiben zusammen. Vorhandene Nutzeränderungen erhalten. |
| B29 | 4 | 0 | 1 | Die beiden Vertauschungsgesetze sind jeweils eine durchgehende Gleichheitsrechnung; das Additionsbeispiel ist eine kurze Satzbündelung. |
| B30 | 1 | 0 | 0 | Ein kurzer Beweis ergänzt die bereits verfügbare Halbgruppenstruktur um die Idempotenz. |
| B31 | 9 | 4 | 2 | Die großen Koordinaten- und Rekonstruktionsbeweise waren bereits gegliedert; einzelne kurze Sandwich- und Bijektionsschlüsse bleiben zusammen. |
| B32 | 1 | 0 | 0 | Drei Zeilen bündeln die schon bewiesene Kommutativität und Idempotenz der Vereinigung. |
| B33 | 3 | 0 | 1 | Eindeutigkeit des Nullelements ist eine Gleichheitskette; das Zahlenbeispiel greift nur vorhandene Strukturgesetze ab. |
| B34 | 2 | 0 | 0 | Einzelne Kürzungseigenschaft und kurze Strukturübernahme. |
| B35 | 5 | 0 | 0 | Die Kürzungsargumente beweisen jeweils dieselbe einzelne Zielgleichheit; kurze Strukturübernahmen bleiben zusammen. |
| B36 | 2 | 0 | 0 | Zwei kurze Bündelungen zuvor bewiesener links-/rechtsseitiger Kürzbarkeit. |
| B37 | 38 | 3 | 11 | Kurze Existenz-/Eindeutigkeitszusammenführungen und reine Definitionsentfaltungen bleiben zusammen; ausführliche Struktur- und Rekonstruktionsargumente wurden gegliedert. |
| B38 | 41 | 4 | 11 | Bloße Typisierungs- und Neutralitätsbündel aus bereits bewiesenen Sätzen bleiben zusammen; die längeren unabhängigen Strukturteile sind getrennt. |
| B39 | 38 | 3 | 4 | Kurze Zusammenführungen vorhandener Homomorphismus-/Isomorphismuskriterien bleiben zusammen; additive und multiplikative Nachweise sind getrennt. |
| B40 | 84 | 22 | 10 | 22 bereits gegliederte Beweise beibehalten; reine Strukturzugriffe, kurze Satzbündelungen und durchgehende Gleichheitsrechnungen bleiben zusammen. |
| B41 | 5 | 1 | 0 | Der Gruppenquadratbeweis war bereits geteilt; die übrigen vier Beweise sind zusammenhängende Strukturzugriffe bzw. Kardinalitäts-/Rekonstruktionsargumente mit jeweils einem Ziel. |
| B42 | 68 | 7 | 8 | Die getrennt bewiesenen Halbverbandsaxiome werden in kurzen Charakterisierungssätzen nur gebündelt; Suprema/Infima und mehrteilige Verbandsnachweise wurden gegliedert. |
| B43 | 122 | 17 | 6 | Die meisten Eigenschaftsnachweise sind bereits eigene Theoreme; deren kurze Frankl-Familienbündelungen bleiben zusammen. Ausführliche Richtungs-/Fallbeweise wurden geteilt. |
| B44 | 44 | 0 | 11 | Definitionsidentische Konvergenz-/Cauchy-Begriffe und die direkte Vererbung einer Metrik werden gemeinsam behandelt; Fließtext bleibt Fließtext. |

## Bearbeitete Beweise

Die Zeilenangabe bezeichnet den Stand vor diesem Audit und dient nur der Identifikation; spätere Umnummerierungen können sie verschieben.

### B22

- Ausgangszeile 589, **Typisierung der Endpunkte eines Walks**: Folgentypisierung und Startindex; Endindex und Endpunkttypisierung.

### B26

- Ausgangszeile 240, **Indexangaben für einen Weganfang**: Typisierung und Schranke des Schnittindex; Inklusion der Anfangsabschnitte.
- Ausgangszeile 383, **Anfangsabschnitt eines endlichen Walks**: Typisierung der eingeschränkten Folge; Kantenbedingung des Anfangsabschnitts; Erhaltung der Endpunkte.
- Ausgangszeile 505, **Schwanzsegment eines endlichen Pfads**: Konstruktion der verschobenen Folge; Injektivität; Kantenbedingung und Pfadstruktur; Endpunkte und Existenzschluss.
- Ausgangszeile 723, **Frische Fortsetzung eines endlichen Pfads**: Konstruktion, Injektivität und Bild; Werte auf dem alten und dem neuen Index; Kantenbedingung und Pfadstruktur; Endpunkte und Existenzschluss.
- Ausgangszeile 1558, **Ein endlicher Weg ist durch zwei anschließende Abschnitte bestimmt**: Gleichheit der Abschnittslängen; Übereinstimmung auf dem Anfangsabschnitt; Übereinstimmung auf dem Endabschnitt; Zusammenführung und Funktionsextensionalität.
- Ausgangszeile 1699, **Reduktion an einem gemeinsamen inneren Wegknoten**: Wahl der Schnittstellen und Wegabschnitte; Strikte Verkürzung der Anfangsabschnitte; Fall verschiedener Anfangsabschnitte; Fall gleicher Anfangsabschnitte; Zusammenführung der Fälle.
- Ausgangszeile 2114, **Zugriff auf die Waldaxiome**: Schlichte Graphenstruktur; Eindeutigkeit der Wege.
- Ausgangszeile 2418, **Zugriff auf die Baumaxiome**: Graphenstruktur und Nichtleerheit; Existenz und Eindeutigkeit der Wege.
- Ausgangszeile 2458, **Jeder Baum ist ein nichtleerer Wald**: Graphenstruktur und Nichtleerheit; Waldeigenschaft und Schluss.
- Ausgangszeile 3284, **Blätter und innere Knoten zerlegen den Träger**: Vollständigkeit der Fallunterscheidung; Disjunktheit von Blättern und inneren Knoten.

### B27

- Ausgangszeile 4171, **Operatorfunktion eines binären Operators (Definitionsbeweis)**: Wohldefiniertheit und Funktionstypisierung; Auswertung an geordneten Paaren.
- Ausgangszeile 4248, **Existenz und Eindeutigkeit der Linksfaltung**: Übersetzung der Rekursionsbedingungen; Existenz der Linksfaltung; Eindeutigkeit der Linksfaltung.
- Ausgangszeile 4935, **Der Erzeugungsschritt ist eine Abbildung**: Typisierung der Blattcodes; Typisierung der Knotencodes; Abschluss und Abbildungseigenschaft.

### B29

- Ausgangszeile 165, **Die Vereinigung bildet auf einer Potenzmenge eine kommutative Halbgruppe**: Abgeschlossenheit; Assoziativität und Halbgruppenstruktur; Kommutativität.

### B31

- Ausgangszeile 488, **Endliche echte Rechtecksbänder erkennen Einermengen**: Multiplikative Erkennung der Projektionen; Klassengrößen und ihr Transport; Einermengenschicht und induzierter Isomorphismus.
- Ausgangszeile 596, **Sandwichgleichheiten der erweiterten Abbildungen**: Inklusion des Sandwichprodukts; Gleichheit und Transport.

### B33

- Ausgangszeile 145, **Eine konstante Operation bildet eine Halbgruppe mit Nullelement**: Abgeschlossenheit der konstanten Operation; Assoziativität und Halbgruppenstruktur; Beidseitige Nullabsorption.

### B37

- Ausgangszeile 691, **Index--Perioden-Satz für endliche Halbgruppen**: Existenz; Eindeutigkeit.
- Ausgangszeile 797, **Größe der von einem Element erzeugten Unterhalbgruppe**: Darstellung durch beschränkt viele Potenzen; Endlichkeit und Kardinalität.
- Ausgangszeile 864, **Ein geeignetes Periodenvielfaches ist positiv und liegt ab dem Index**: Natürliche Zahl und Positivität; Vergleich mit dem Index.
- Ausgangszeile 957, **Existenz eines kleinsten nichtleeren Ideals**: Existenz eines minimalen Ideals; Kleinheit unter allen nichtleeren Idealen.
- Ausgangszeile 1142, **Nummerierte Tafeln transportieren die Halbgruppenstruktur**: Transportgleichung; Assoziativität; Endlichkeit und Isomorphismus.
- Ausgangszeile 1284, **Die Umbenennung ist eine Wirkung auf der Menge der assoziativen Operationen**: Typisierung der Operation und der Permutationen; Erhaltung der Assoziativität; Identitäts- und Kompositionsgesetz.
- Ausgangszeile 1359, **Die Umbenennungsrelation ist der Graph der Wirkung**: Von der Umbenennungsrelation zur Wirkungsformel; Von der Wirkungsformel zur Umbenennungsrelation.
- Ausgangszeile 1427, **Umbenennungsorbits sind die Isomorphieklassen auf dem festen Träger**: Vom Orbit zur Isomorphie; Von der Isomorphie zum Orbit.
- Ausgangszeile 1553, **Der kanonische Tafelcode ist vollständig**: Isomorphie erhält den Tafelcode; Gleicher Tafelcode liefert Isomorphie.
- Ausgangszeile 2025, **Rekonstruktion bei erhaltener Einermengenschicht**: Konstruktion der Bijektion; Operationserhaltung.
- Ausgangszeile 2095, **Potenzhalbgruppen bestimmen Halbgruppen der Ordnung zwei**: Vollständige Prüfung der assoziativen Tafeln; Bestimmung der fünf Isomorphieklassen; Unterscheidung durch die Potenzhalbgruppen.

### B38

- Ausgangszeile 122, **Existenz und Eindeutigkeit des neutralen Elements**: Existenz eines neutralen Elements; Eindeutigkeit.
- Ausgangszeile 280, **Monoidales Quadrat und sein Potenzträger**: Potenzmonoid und erste Trägerinklusion; Umgekehrte Trägerinklusion; Transport der Monoidstruktur.
- Ausgangszeile 330, **Elemente der neutralen Menge wirken neutral auf dem Quadrat**: Trägerzugehörigkeit der neutralen Elemente; Links- und Rechtsneutralität auf dem Quadrat.
- Ausgangszeile 378, **Monoidstruktur des Potenzquadrats erkennt das Grundquadrat**: Einermengigkeit des neutralen Mengenprodukts; Monoidstruktur des Grundquadrats.
- Ausgangszeile 435, **Monoidkriterium für Produktquadrate**: Vom Potenzquadrat zum Grundquadrat; Vom Grundquadrat zum Potenzquadrat.
- Ausgangszeile 1611, **Ein Halbgruppenisomorphismus transportiert die Monoidstruktur**: Halbgruppenstruktur und Typisierung der Eins; Beidseitige Neutralität im Ziel.
- Ausgangszeile 1667, **Ein Halbgruppenisomorphismus erhält und reflektiert inverse Paare**: Transportdaten und Erhaltung inverser Paare; Reflexion inverser Paare.
- Ausgangszeile 1716, **Halbgruppenisomorphismen zwischen Monoiden erhalten Einheiten**: Erhaltung der Einheiten; Reflexion der Einheiten.
- Ausgangszeile 1797, **Komposition von Monoidhomomorphismen**: Erhaltung der Halbgruppenoperation; Erhaltung der Eins und Monoidstruktur.
- Ausgangszeile 200, **Neutrale Elemente von Potenzhalbgruppen sind Einermengen**: Die neutrale Menge ist eine Einermenge; Die Grundhalbgruppe ist ein Monoid.
- Ausgangszeile 941, **Einheiten einer Potenzhalbgruppe**: Einheiten der Potenzhalbgruppe sind Einermengen von Einheiten; Einermengen von Einheiten sind Einheiten.

### B39

- Ausgangszeile 266, **Komposition von Halbringhomomorphismen**: Additiver Monoidanteil; Multiplikativer Monoidanteil und Schluss.
- Ausgangszeile 421, **Die natürlichen Zahlen bilden einen Halbring mit Eins**: Additive und multiplikative Monoidstruktur; Distributivität; Nullabsorption und Halbringstruktur.
- Ausgangszeile 1124, **Additiver Monoidanteil der kanonischen Abbildung**: Funktionstypisierung und Additionserhaltung; Nullerhaltung und Monoidanteil.
- Ausgangszeile 1163, **Multiplikativer Monoidanteil der kanonischen Abbildung**: Funktionstypisierung und Multiplikationserhaltung; Einserhaltung und Monoidanteil.

### B40

- Ausgangszeile 2927, **Die formalen Differenzen bilden ein kommutatives Monoid**: Monoidstruktur; Kommutativität.
- Ausgangszeile 3149, **Die kanonische Einbettung ist ein Monoidhomomorphismus**: Trägerabbildung und Operationserhaltung; Erhaltung des neutralen Elements.
- Ausgangszeile 3297, **Vertauschte formale Differenzen sind inverse Klassen**: Erste inverse Gleichung; Zweite inverse Gleichung.
- Ausgangszeile 3439, **Die formalen Differenzen bilden eine abelsche Gruppe**: Gruppenstruktur; Kommutativität.
- Ausgangszeile 4113, **Jeder Ring mit Eins ist ein Halbring mit Eins**: Additive und multiplikative Monoidstruktur; Distributivität; Nullabsorption und Halbringstruktur.
- Ausgangszeile 4277, **Komposition von Ringhomomorphismen**: Additiver Gruppenanteil; Multiplikativer Monoidanteil und Schluss.
- Ausgangszeile 5639, **Die kanonische Ganzzahlabbildung ist ein Ringhomomorphismus**: Additiver Gruppenhomomorphismus; Multiplikativer Monoidanteil und Ringhomomorphismus.
- Ausgangszeile 586, **Nichtleere endliche kürzbare Halbgruppen sind Gruppen**: Bijektivität der Translationen; Beidseitig neutrales Element; Beidseitige Inverse und Gruppenstruktur.
- Ausgangszeile 1118, **Große Potenzhalbgruppen rekonstruieren die Einheitengruppen**: Transport der Einheitenstabilität; Bild der gesamten Einheitengruppe; Bild der nichtleeren Teilmengen der Einheitengruppe.
- Ausgangszeile 1208, **Einseitige Gruppenstarrheit der großen Potenzhalbgruppe**: Monoidstruktur des Zielträgers; Gruppenstruktur des Zielträgers; Rekonstruktion des Gruppenisomorphismus.

### B42

- Ausgangszeile 327, **Komposition von Halbverbandshomomorphismen**: Funktionstypisierung der Komposition; Erhaltung der Halbverbandsoperation.
- Ausgangszeile 621, **Ein supremal gelesener Halbverband induziert eine partielle Ordnung**: Reflexivität; Transitivität; Antisymmetrie und Ordnungsstruktur.
- Ausgangszeile 765, **Die Halbverbandsoperation liefert das Paarsupremum**: Eigenschaft als obere Schranke; Kleinste obere Schranke.
- Ausgangszeile 1317, **Die Halbverbandsoperation liefert das Paarinfimum**: Obere Schranke in der supremalen Ordnung; Kleinste obere Schranke; Paarinfimum in der dualen Ordnung.
- Ausgangszeile 1880, **Komposition von Verbandshomomorphismen**: Erhaltung des Infimums; Erhaltung des Supremums; Trägerabbildung und Verbandshomomorphismus.
- Ausgangszeile 2082, **Potenzmengen bilden Verbände**: Halbverbandsaxiome des Durchschnitts; Halbverbandsaxiome der Vereinigung; Absorption und Verbandsstruktur.
- Ausgangszeile 2807, **Paarinfima in endlichen Halbverbänden mit Nullelement**: Endlichkeit und Nichtleerheit der unteren Schranken; Maximales und größtes unteres Element; Paarinfimum und Existenzschluss.
- Ausgangszeile 3331, **Die echten unteren Elemente bilden eine endliche nichtleere Teilmenge**: Nichtleerheit der echten unteren Elemente; Trägereinschluss und Endlichkeit.

### B43

- Ausgangszeile 3689, **Beschränkter Existenzquantor über einer Adjunktion**: Zerlegung eines Existenzzeugen; Einführung eines Existenzzeugen.
- Ausgangszeile 3771, **Beschränkter Allquantor über einer Adjunktion**: Einschränkung auf die beiden Teile; Zusammenführung der beiden Allbedingungen.
- Ausgangszeile 4387, **Die erweiterte Familie ist vereinigungsabgeschlossen**: Vereinigungen mit einem Mitglied der ursprünglichen Familie; Vereinigungen mit der leeren Menge; Zusammenführung und Abschluss.
- Ausgangszeile 4527, **Die Familie gemeinsamer oberer Elemente ist endlich und nichtleer**: Trägereinschluss und gemeinsames oberes Element; Endlichkeit und Schluss.
- Ausgangszeile 5242, **Reduktion auf Frankl-Familien mit leerer Menge**: Einschränkung auf Familien mit leerer Menge; Rücktransport von der erweiterten Familie.
- Ausgangszeile 5318, **Charakterisierung eines privaten Punkts**: Ein privater Punkt erzwingt die Inklusion; Die Inklusion enthält den privaten Punkt; Übersetzung in den Hauptfilter.

### B44

- Ausgangszeile 214, **Die diskrete Metrik ist eine Metrik**: Positivität, Definitheit und Symmetrie; Dreiecksungleichung.
- Ausgangszeile 297, **Kugelverkleinerung**: Positivität des kleineren Radius; Inklusion der kleineren Kugel.
- Ausgangszeile 483, **Restfolgen haben denselben metrischen Grenzwert**: Von der Folge zur Restfolge; Von der Restfolge zur Folge.
- Ausgangszeile 541, **Reelle und metrische Beschränktheit stimmen überein**: Nichtleerheit der Wertemenge; Von einer reellen Schranke zur Kugel; Von einer Kugel zur reellen Schranke.
- Ausgangszeile 882, **Identität und konstante Abbildungen sind stetig**: Stetigkeit der Identität; Stetigkeit der konstanten Abbildung.
- Ausgangszeile 954, **Folgenkriterium für metrische Stetigkeit**: Stetigkeit erhält Folgengrenzwerte; Das Folgenkriterium erzwingt Stetigkeit.
- Ausgangszeile 1098, **Wachsende Aufzählung unendlicher Mengen natürlicher Zahlen**: Nichtleerheit und Unbeschränktheit; Wohldefinierter Nachfolgerschritt; Rekursion und Eigenschaften der Aufzählung.
- Ausgangszeile 1284, **Konvergenz in der diskreten Metrik**: Konvergenz erzwingt schließlich konstante Werte; Schließlich konstante Werte liefern Konvergenz.
- Ausgangszeile 1299, **Eine beschränkte, nicht folgenkompakte Metrik**: Beschränktheit; Fehlende Folgenkompaktheit.
- Ausgangszeile 1330, **Satz von der monotonen Teilfolge**: Unendlich viele Spitzenindizes; Endlich viele Spitzenindizes.
- Ausgangszeile 1054, **Isometrien erhalten die metrische Struktur**: Stetigkeit; Erhaltung der Cauchy-Eigenschaft.

## Konkrete Korrekturen und Prüfung

- B26, „Ein endlicher Weg ist durch zwei anschließende Abschnitte bestimmt“: Ab ursprünglichem Schritt 34 waren mehrere Zeilenverweise noch um eins erhöht. Die Verweise auf die vorausgehende Schranke, die Auswertung der beiden Endabschnitte, den Existenzschluss und die Funktionsextensionalität wurden auf die tatsächlich bewiesenen Vorgängerzeilen zurückgesetzt. Keine Zahlen in Formeln oder Theoremschlüsseln wurden dabei verändert.
- B44, „Isometrien erhalten die metrische Struktur“: Beide behaupteten Eigenschaften haben nun jeweils einen eigenen expliziten Nachweis durch Abstandserhaltung.
- B27: Auf Anweisung der koordinierenden Aufgabe wurde die bandlokale Neudefinition von `proofstepwidestar` samt Save/Restore entfernt, weil die gemeinsame Implementierung dieselbe Darstellung bereitstellt. Die vorhandenen Umbruchhilfen für Regelargumente und Referenzen bleiben erhalten.
- Automatischer Inhaltsvergleich aller 638 Beweise: Bis auf die vorstehend dokumentierten B26-Verweiskorrekturen und die Präzisierung des Isometriebeweises ist der bisherige Beweistext nach Abzug der neu eingefügten Gliederungsbefehle identisch.
- Explizite TeX-Umgebungen sind in allen 22 Dateien balanciert; alle neuen Fortsetzungszähler stimmen mit der ursprünglichen Schrittfolge überein. Keine globale Makroänderung und kein eigener Vollbuild. Die koordinierende Aufgabe übernimmt gemeinsame Tabellenformatierung, weitere Auflösung verschachtelter Prämissen und die Buildprüfung.


## Ergänzung: explizite Theorem-Prämissen (Nutzerpunkt 2)

Alle aktiven Bände B22–B44 außer B26 und B28 wurden nochmals vollständig auf verschachtelte Theorem-Anwendungen geprüft, einschließlich der Anwendungen in `ProofRefStack`-/`BandXXIXProofRefStack`-Layouts. Insgesamt wurden **242 konkrete Zwischenzeilen** eingefügt. Die Schlussformeln, Theoremschlüssel und mathematischen Zahlen bleiben erhalten; nummerische Abhängigkeiten, Regelargumente und Fortsetzungszähler wurden angepasst.

| Band | Neue Zwischenzeilen |
|---|---:|
| B22 | 2 |
| B23 | 5 |
| B24 | 2 |
| B27 | 37 |
| B29 | 1 |
| B31 | 2 |
| B37 | 2 |
| B38 | 21 |
| B39 | 5 |
| B40 | 68 |
| B41 | 11 |
| B42 | 24 |
| B43 | 62 |

B24/B29/B31 und die Bände ohne zahlreiche Verschachtelungen wurden ebenso vollständig erfasst wie die langen B27/B40/B43. Es handelt sich um eine Vollinventur, keine Stichprobe.

Vier durch eingeschobene Prämissen unterbrochene Gleichungs-/Äquivalenzketten erhielten ihre jeweils zuvor implizite linke Seite ausdrücklich (B40 zweimal, B42/B43 je einmal).

Konkrete Korrektur in B43: Aus `t\neq0` war bisher mittels Gleichheitssymmetrie unmittelbar `0\neq t` gefolgert worden. Jetzt stehen die Implikation `0=t\rightarrow t=0` und ihr Modus-Tollens-Schluss als eigene Zeilen. In B41 wurden die beiden in Faserargumenten benötigten Potenzhalbgruppen ausdrücklich als `Q_S` und `Q_T` typisiert.

### Bewusst verbleibende Fälle

Der erneute strukturelle Scan findet nur drei Theorem-in-Theorem-Anwendungen im zugewiesenen Scope: B27 Baumpositionsrekursion (zwei reine definitorische Ersetzungen innerhalb derselben bereits bewiesenen Existenzformel), B31 Linksargumentkongruenz nach Gleichheitssymmetrie, B31 Symmetrie nach Rechtsargumentkongruenz. Diese drei sind reine Gleichheits-/Definitionsumschreibungen und benötigen keine weitere Sachprämisse.

Weitere knappe logische Symmetrie-, Kongruenz-, Doppelnegations- und Ex-falso-Anwendungen in Regelargumenten bleiben dort erhalten, wo sie nur eine bereits nummerierte Aussage umschreiben. Nebeneinanderstehende unabhängige Quellenangaben und reine Layoutwrapper werden nicht als verschachtelte Prämissen behandelt. Die schematische Einführung von Gleichheitsimplikation/Allquantor mit bereits verfügbaren Theoremsequenzen ist ebenfalls keine versteckte Sachprämisse.

Maschinenlesbare Änderungsnachweise stehen unter `tmp/proof-audit/lifts-b22-b44-ledger.json`, `stage2-ledger-b22-b44.json`, `chain-starts-b22-b44.json` und `final-nested-b22-b44.json`. Der Vergleich der ersten Hebungsrunde bestätigte alle ursprünglichen Formelargumente als unveränderte Teilfolge. Es wurde vereinbarungsgemäß keine eigene Buildkette gestartet.


## Nachauftrag: B19 und B26 sowie konkrete Indexkorrekturen

B19 erhielt **121 weitere Zwischenzeilen** (106 reguläre Hebungen, 14 in mehrzeiligen Begründungsfeldern, eine zusätzliche Positivitätsprämisse). Im Abschlussbeweis zum vollständigen angeordneten Körper werden die Tabellenzahlen zwischen den beiden Proofparts nun fortgeführt; die Vollständigkeitsannahmen werden ausdrücklich entlassen. Die zuvor sich selbst zitierende Schlusszeile wurde korrigiert.

B26 erhielt **128 weitere Zwischenzeilen** (123 reguläre Hebungen, fünf zusätzliche Typisierungsschritte). Die beiden Anwendungen `NatSeg(n+1) ⊆ N` führen jetzt zuerst `n+1 ∈ N` her. Bei der Auswertung des Schwanzsegments an Null wird ausdrücklich `0 ∈ NatSeg(n+1)` bewiesen. Im Schwanz-Induktionsschritt wurden 14 bereits vorhandene falsche/verschobene Begründungen und die betroffenen Annahmeabhängigkeiten korrigiert; der abschließende arithmetische Schritt verwendet jetzt die benötigte Kommutativität unter dem äußeren Summanden und die passende Assoziativitätsrichtung.

Beim Satz `InternallyDisjointPathsFormCycleCore` wurde die bisher nur durch vier ineinandergesteckte Wegoperationen unter `rIE` begründete Knotenbedingung tatsächlich bewiesen: Endpunkte verwenden die gegebenen beziehungsweise umgekehrten Wege; für einen inneren Knoten `z=p(i)` wird das Endstück von `p` dem rückwärts durchlaufenen Anfang von `p` mit anschließendem `q` gegenübergestellt. Die Fallbegründung behandelt Typisierung, Kanten, Injektivität, Bilder, Schnitt und Verschiedenheit. Die Formel und das Tabellenformat des ursprünglichen Schlusses bleiben erhalten.

B43: Im Rücktransport eines halbhäufigen Elements war der Existenzzeuge Zeile 4, wurde aber ab Zeile 5 referenziert. Die vier Folgeschritte wurden berichtigt. Der abschließende Proofpart zur unveränderten enthaltenden Teilfamilie erhielt seine fehlende Frankl-Familien-Annahme; seine drei weiteren Zeilen benutzen nun lokale gültige Referenzen.

Die vermeintlich falschen B27-Referenzen bei Blattwort und Baumauswertung sind nach Prüfung **korrekt**: Die beiden Hilfsmakros `BXXVIIProofTreeLeafWordIota` und `BXXVIIProofTreeEvaluationIota` expandieren zwei bzw. drei nummerierte Tabellenzeilen. Ein rein lexikalischer Zähler ohne Makroexpansion meldet dort fälschlich Selbst-/Vorwärtsverweise; diese Referenzen wurden daher bewahrt.

Abschlusskontrolle: B19/B26 enthalten keine `FormulaRefAuto`-in-`FormulaRefAuto`-Prämissen mehr. Für B19/B26/B43 verbleiben keine wörtlichen Selbst-/Vorwärtsreferenzen in Theorem-Argumentlisten. B19 und B26 besitzen nach der Bearbeitung auch keine leere linke Kettenseite unmittelbar nach einer eingefügten Einzelzeile. Die ergänzenden Nachweise liegen in `b19-agent-ledger.json`, `b19-agent-extra-ledger.json`, `b19-axiom-fix-ledger.json`, `b26-agent-ledger.json`, `b26-typefix-ledger.json` und `agent-final-direct-indices.json` unter `tmp/proof-audit`.


## Erneuter B27-Indizescheck einschließlich logischer Regeln

Alle 30 Verdachtsfälle aus `all-index-candidates.json` sind nach Lesekontrolle der Makrodefinitionen und ihrer Aufrufstellen Fehlalarme: Die gemeinsamen Vorspanne erzeugen 3 Schritte (Linksfaltung), 21 Schritte (Knotenkürzung), 2 Schritte (Positionsmenge), 2 Schritte (Blattwort) beziehungsweise 3 Schritte (Baumauswertung). Der lexikalische Scanner zählt diese Aufrufe nicht mit. Sämtliche beanstandeten Indizes bezeichnen bereits vorhandene, inhaltlich passende Prämissen; keine Quellkorrektur erforderlich. Einzelbelege und tatsächliche Zeilennummern: `tmp/proof-audit/b27-expanded-index-confirmation.json`.
