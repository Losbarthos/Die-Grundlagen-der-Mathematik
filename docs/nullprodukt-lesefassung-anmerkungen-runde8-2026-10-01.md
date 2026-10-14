# Nullprodukt-Rekonstruktion: achte Anmerkungsrunde

**Stand: 1. Oktober 2026; alle Änderungen, PDF-Prüfungen und der reMarkable-Abgleich sind abgeschlossen.** Dieser Bericht dokumentiert die gelesenen Anmerkungen, ihre Umsetzung und die Prüfungen.

## Ausgangsmaterial und Seitenbezug

Das unveränderte annotierte Original liegt unter
[tmp/pdfs/nullproducts-annotations-2026-10-01/annotations-original.pdf](../tmp/pdfs/nullproducts-annotations-2026-10-01/annotations-original.pdf).
Die Ausgangsfassung hat **36 physische PDF-Seiten**. `source-01.png` bis
`source-36.png` im selben Verzeichnis bilden die Seiten für die Sichtprüfung
ab. Die Druckseiten beginnen nach der Titelseite; daher entspricht etwa
PDF-Seite 24 der Druckseite 23.

Die handschriftlichen Änderungswünsche verteilen sich auf **neun Seiten**:
6, 8, 10, 12, 13, 15, 24, 25 und 28. Auf Seite 25 stehen zwei getrennte
Wünsche, insgesamt also **zehn inhaltliche Hinweise**. Seite 27 enthält
zusätzlich zahlreiche bestätigende Häkchen und eigene Formelskizzen.
Diese wurden gelesen, aber nicht als weitere Änderungsaufträge gezählt.
Die übrigen Markierungen sind Häkchen; weitere Seiten sind unbeschrieben.
Technische Unterschiede der Seitenobjekte gegenüber dem Ausgangs-PDF
sind kein verlässliches Maß für die Anzahl handschriftlich kommentierter
Seiten.

## Hinweise und Umsetzung

| PDF-Seite / Druckseite | Hinweis | Umsetzung in den Quellen |
| --- | --- | --- |
| 6 / 5 | Die konkrete Dreierhalbgruppe deutlicher von der allgemeinen Halbgruppe S unterscheiden; passende Legende. | Die konkrete Halbgruppe heißt durchgehend S_Bsp. Auch ihre Produktfamilie, Profile, Präordnung und L-, D-, C-, E-Familien erhalten eigene Beispielindizes und Legendeneinträge. |
| 8 / 7 | Allgemeine Aussagen zur Erhaltung von Mächtigkeiten und Produktquadraten unter Isomorphismen verwenden; die Endlichkeit der Quadrate beachten. | Die vorhandenen Sätze `SemigroupIsoSquareImage`, `SemigroupIsoSquareRestriction`, `FiniteBijectionCardEquality` und `SemigroupSquareSubset` werden sichtbar eingebunden. Angewandt werden sie auf den gegebenen Isomorphismus der Potenzhalbgruppen. Ein noch zu beweisender Isomorphismus S≅T wird dabei nicht vorausgesetzt. |
| 10 / 9 | Prüfen, ob aus isomorphen Potenzhalbgruppen und einer Null in S allgemein eine Null in T folgt; gegebenenfalls eigene Lesefassung und Tabellen sowie einen Hinweis in Band 28 ergänzen. | Der allgemeine Satz `PowerSemigroupZeroTransport` wird als eigenständige Ergänzung mit Lesefassung und Beweistabellen unter der Nummerierung 28Z ausgearbeitet. Er gilt auch für unendliche Halbgruppen und ohne Begrenzung der Produktwerte. Band 28 erhält einen weiterführenden Hinweis; die Nullprodukt-Lesefassung verwendet den Satz unmittelbar. |
| 12 / 11 | Die Nullpräordnung allgemein im passenden Fachband bei den Annihilatoren verankern. | Die bereits vorhandene Definition `NullProfilePreorderDef` aus Band 33 wird unmittelbar verlinkt. Der Text nennt ausdrücklich die allgemeine Voraussetzung einer Halbgruppe mit Null. Endlichkeit und zwei Produktwerte sind hier nicht nötig. |
| 13 / 12 | „analog zu ≼_S“; die ausgeschriebene Gleichheit der Nulltests direkt in Band 33 integrieren. | Neben der vorhandenen Definition `NullProfileEquivalenceDef` steht neu der Satz `NullProfileEquivalentTests` mit der ausgeschriebenen Testäquivalenz und vollständiger Lemmon-Tabelle. |
| 15 / 14 | Auch die Profilklasse [A]_S in Band 33 verankern, wie die vorherigen Begriffe. | Unmittelbarer Verweis auf `NullProfileSetsDef`; die Lesefassung erläutert, dass diese Klassenbildung für jede Halbgruppe mit Null gilt. |
| 24 / 23 | Den Transport der Präordnungsvergleiche allgemein beweisen und nach Band 33 auslagern. | Der bereits allgemeine Satz `NullProfileIsoPreorder` wird direkt genannt. Seine Voraussetzungen werden vor der anschließenden Erklärung aufgeführt. |
| 25 / 24, oben | Die Ordnungserhaltung beziehungsweise Ordnungsisomorphie von ψ allgemein in Band 33 zeigen. | Die induzierte Abbildung wird mit `NullProfileInducedMapDef` und `NullProfileInducedMapValue` verknüpft; `NullProfileIsoOrder` und `NullProfileIsoBijection` belegen die beiden Eigenschaften. |
| 25 / 24, unten | Die Bijektion zwischen den unteren Mengenfamilien ebenfalls allgemein in Band 33 zeigen. | Direkter Verweis auf `NullProfileLowerTransport`. Der Text sagt ausdrücklich, dass der Transport weder Endlichkeit noch eine Beschränkung der Produktwerte voraussetzt. |
| 28 / 27 | „Warum kann man für T die gleiche Beschreibung wählen. Liegt das an der 0 in T?“ | Die Identität E_r^T=D_r^T\C_r^T=⋃_{q<r}C_q^T wird elementweise erklärt. Sie folgt aus den Mengendefinitionen und der Profilordnung. Die Nulleigenschaft wird für diese Zerlegung nicht erneut verwendet. |

Auf PDF-Seite 27 / Druckseite 26 bestätigen Häkchen insbesondere die
Zerlegung in exakte und strikt kleinere Profilfasern. Die dortigen privaten
Notizen wie „px=0 ⇒ qx=0“ werden nicht als Formeln des Skripts übernommen:
p und q sind Profilklassen und keine Faktoren eines Mengenprodukts.
Die ergänzte Erklärung wählt stattdessen einen Vertreter B von p. Dann
bedeutet [{s}]_S≤p für jede nichtleere Testmenge X genau die beiden
Implikationen BX={0}⇒{s}X={0} und XB={0}⇒X{s}={0}.

## Die neue allgemeine Grundlage zum Nullelement

Der Satz lautet: Ist Φ:P_*(S)→P_*(T) ein Halbgruppenisomorphismus und
besitzt S eine Null 0_S, dann besitzt T eine Null 0_T, und
Φ({0_S})={0_T}. Endlichkeit wird nicht benötigt.

Die stärkere Aussage lässt sich nicht allein daraus ablesen, dass
Z=Φ({0_S}) eine Null der Potenzhalbgruppe ist. Beispielsweise ist die
gesamte Trägermenge einer Gruppe eine Null ihrer nichtleeren
Potenzhalbgruppe. Es muss zusätzlich gezeigt werden, dass gerade dieses
Bild Z eine Einermenge ist.

Der neue Beweis verwendet die eindeutig bestimmten nichtleeren Mengen
A_z=Φ⁻¹({z}) für z∈Z und ihre Vereinigung W=⋃_{z∈Z}A_z. Aus
{z}Z=Z und der Produkterhaltung folgt

\[
A_zW=\bigcup_{w\in Z}A_zA_w
     =\bigcup_{w\in Z}A_{zw}
     =\bigcup_{v\in Z}A_v=W.
\]

Die letzte Gleichheit benutzt, dass die Produkte zw ganz Z durchlaufen.
Daher lässt jedes {z} die Menge Φ(W) durch Linksmultiplikation fest.
Zusammen ergibt das ZΦ(W)=Φ(W). Weil Z zugleich die Potenznull ist,
gilt ZΦ(W)=Z. Somit ist Φ(W)=Φ({0_S}), und die Injektivität liefert
W={0_S}. Jedes A_z ist eine nichtleere Teilmenge von W, also selbst
{0_S}. Daraus folgt Z={z}. Die Absorption von Z gegen Einermengen
ergibt schließlich zt=tz=z für jedes t∈T.

Die Vereinigungen werden jeweils innerhalb einer der beiden
Potenzhalbgruppen berechnet. **Eine Erhaltung von Vereinigungen durch Φ
wird nicht vorausgesetzt.** Ebenso wird nicht behauptet, dass Φ sämtliche
Einermengen erhält. Die Mengen A_z sind Funktionswerte von Φ⁻¹; ihre
Festlegung benötigt keine Auswahl beliebiger Urbilder.

Die zugehörigen Quellen sind die
[Lesefassung zum Nullelement-Transport](../tex/b28/zero-transport/reading.tex),
die [Beweistabellen](../tex/b28/zero-transport/proofs.tex) und das
[Editionssetup](../tex/b28/zero-transport/edition-setup.tex).
Diese Ergänzung verwendet die Nullgrundlagen aus Band 33 und die
Potenzhalbgruppen aus Band 28. Die eigene Nummerierung 28Z verhindert,
dass hierfür alte Satznummern in Band 28 oder Band 33 verschoben werden.
Die Ergänzung enthält 13 registrierte Aussagen und 262 Lemmon-Zeilen.
Der Abhängigkeitsaudit findet weder Fehler noch manuelle Parserausnahmen.
Alle 21 PDF-Seiten der beiden Fassungen wurden nach den letzten
Umbruchkorrekturen frisch gerendert und visuell geprüft.

## Einordnung in die vorhandenen Beweise

In [algebra-zero.tex](../tex/b37/nullproducts/algebra-zero.tex) erhält
`NPTargetZero` einen neuen **17-zeiligen Kurzbeweis**. Der allgemeine
Nulltransport liefert zuerst z. Aus zz=z folgt z∈T². Die bereits bekannte
Zweiergröße von T² ermöglicht dann die Benennung des anderen Produktwerts
d. Der bisherige **48-zeilige Beweis über die beiden Zweierquadrate**
bleibt vollständig als alternativer Beweis erhalten. Seine algebraischen
Hilfssätze werden nicht entfernt.

Die veröffentlichte Aussage und die semantische ID `NPTargetZero` bleiben
unverändert. Der neue Beweis benötigt die vorhandene Voraussetzung
S²={0,c} selbst nicht; seine letzte Zeile weist diese Voraussetzung
deshalb auch nicht als offene Abhängigkeit aus. Die stärkere bisherige
Satzsignatur bleibt als Schnittstelle für die anschließende Rekonstruktion
bestehen.

In [b33-nullprofiles.tex](../tex/b33-nullprofiles.tex) ist
`NullProfileEquivalentTests` als eigener Schlussabschnitt angefügt.
Der neue Satz **33.3.6.1** schreibt

\[
A\sim_S B\quad\Longleftrightarrow\quad
\forall X\in K_S\;
\bigl((AX=z_S\leftrightarrow BX=z_S)
\land(XA=z_S\leftrightarrow XB=z_S)\bigr)
\]

aus. Seine **29 Lemmon-Zeilen** leiten beide Richtungen allein aus den
vorhandenen Definitionen der Präordnung und der Profilgleichheit sowie
den logischen Regeln ab. Die allgemeineren Profildefinitionen und
Transportsätze waren bereits in Band 33 vorhanden; diese Runde macht ihre
Verwendung an den jeweiligen Stellen der
[Nullprodukt-Lesefassung](../tex/b37/nullproducts/reading.tex) ausdrücklich
sichtbar.

## Notation und Symbollegende

Die konkrete Dreierhalbgruppe heißt S_Bsp; S bezeichnet weiterhin die
allgemeine Ausgangshalbgruppe. Die Umbenennung erfasst auch Indizes in
Profilen, Vergleichen und Mengenfamilien. Für Beispielrechnungen mit einer
Zielhalbgruppe wird ausdrücklich der allgemeine Beweis mit
Ausgangshalbgruppe S_Bsp angewandt. T, Φ und ψ beziehen sich dort auf diese
Anwendung; im allgemeinen Beweis behalten sie ihre ursprünglichen Rollen.

In [symbols.tex](../tex/b37/nullproducts/symbols.tex) sind am 1. Oktober
2026 **54 Deklarationen mit 54 verschiedenen IDs** gezählt worden.
Zu den bisherigen 45 kommen neun Einträge für S_Bsp, M_Bsp, [A]_Bsp,
Q_Bsp, ≼_Bsp und die Beispielversionen von L, D, C und E hinzu.
Das Potenzmengensymbol und gewöhnliche lokale Variablen bleiben weiterhin
außerhalb der Registrierung. Die technische Dokumentation steht in
[symbollegende-lesefassung.md](symbollegende-lesefassung.md).

## Bereits ausgeführte Prüfungen

- Alle 36 Ausgangsseiten wurden visuell gelesen; Änderungswünsche,
  bestätigende Häkchen und private Zwischenrechnungen wurden getrennt.
- Der neue allgemeine Nulltransport wurde unabhängig mathematisch
  gegengeprüft. Insbesondere wurde kontrolliert, dass keine
  Vereinigungsverträglichkeit von Φ und keine Endlichkeit benutzt werden.
- Die neue B33-Tabelle wurde unabhängig auf Regeln, Quantoren und
  Voraussetzungen geprüft. Der Abhängigkeitsaudit meldet für das gesamte
  Modul 659 maschinell geprüfte Zeilen, 13 bereits vorhandene manuell zu
  lesende Schreibweisen und keinen Fehler. Die 29 neuen Zeilen haben
  keine Parserausnahmen.
- B33 ist mit dem neuen Satz gebaut worden. Gegenüber
  `b33-registry-before.tsv` sind alle 139 alten Registryzeilen unverändert
  erhalten. Alle 60 bisherigen AUX-Paare aus Satznummer und Sprungziel
  stimmen mit `b33-aux-before.aux` überein. Neu ist ausschließlich
  `NullProfileEquivalentTests` unter 33.3.6.1.
- Der 17-zeilige Kurzbeweis zu `NPTargetZero` wurde mathematisch und auf
  Regelrichtung geprüft. Für `algebra-zero.tex` meldet der
  Abhängigkeitsaudit 498 geprüfte Zeilen, keine Parserausnahmen und keinen
  Fehler. Die neue Existenzelimination entfernt genau die lokale
  Zeugenannahme.
- Die Beispielumbenennung wurde über die gesamte Lesefassung auf
  verbliebene Mischungen allgemeiner S-Indizes mit p₀ und p₁ geprüft.
  Die notwendige Trennung der Zielanwendung wurde anschließend ergänzt.

Die Abhängigkeitsaudits prüfen die Buchführung offener Annahmen; sie
ersetzen keinen mathematischen Beweisprüfer. Die mathematischen
Gegenprüfungen wurden daher zusätzlich durchgeführt.

## PDF-Prüfung und Veröffentlichung

| Ausgabe | PDF-Seiten |
| --- | ---: |
| Band 28 | 228 |
| Band 33 | 44 |
| Nullprodukt-Rekonstruktion: Lesefassung | 37 |
| Nullprodukt-Rekonstruktion: Beweistabellen | 35 |
| Nullelement-Transport: Lesefassung | 5 |
| Nullelement-Transport: Beweistabellen | 16 |
| Gesamtband | 2742 |

Alle geänderten Fachausgaben wurden mit mindestens zwei LuaLaTeX-Läufen
bis zu stabilen Verweisen gebaut. Die neuen und verschobenen Seiten wurden
visuell geprüft. Die gesamte Nullprodukt-Lesefassung und beide vollständigen
Nulltransport-Fassungen sind geprüft. Der Quellen- und Besitzeraudit der
Nullprodukt-Editionen sowie ihre Nummerierungs- und Verweisprüfungen bestehen.
Die alten Nummern und Ziele in Band 37 bleiben erhalten.

Die Symbollegende enthält 54 unterschiedliche, je einmal eingeführte
Notationen. Ihre 250 Links stimmen im LaTeX-PDF und in der veröffentlichten
Fassung mit der jeweiligen Einführungsseite überein. Auf jeder Seite ist die
Legende genau die Schnittmenge aus tatsächlichen Verwendungen und bereits
eingeführten Symbolen; Potenzmengen und lokale Variablen werden nicht
aufgenommen. Keine Überlappungen oder abgeschnittenen Einträge wurden gefunden.

Band 28 behält alle 647 Registryzeilen; seine vollständige AUX-Datei ist
gegenüber der Ausgangssicherung unverändert. Die bestehenden B33-Nummern
und Sprungziele bleiben ebenfalls erhalten. Der abschließende Grundlagenaudit
prüft 3.897 externe Links in Band 28 und 802 in Band 33 ohne Fehler.

Auch der Gesamtband wurde bis zu stabilen Verweisen gebaut. Sein Audit
gleicht die Satznummern und Registryeinträge mit allen 49 Einzelbänden ab.
Die neuen B33-Tabellenseiten auf PDF-Seiten 2160–2161 und der B28-Hinweis
auf PDF-Seite 2076 wurden im Gesamtband zusätzlich visuell freigegeben.
Nachweise: `audit-main-final.log` und `main-final-b33/`.

Alle sieben betroffenen PDF-Ausgaben sind veröffentlicht. Der globale
PDF-Audit umfasst 74 Dateien, 6.102 Seiten, 64.853 lokale und 45.451 externe
Links; alle Ziele sind gültig. Die Veröffentlichung erhält Seiteninhalte,
Seitengrößen und benannte Ziele unverändert. Der endgültige Vergleich
bestätigt genau fünf ersetzte Dateien und zwei neue Ergänzungen; die 67
weiteren bisherigen PDFs bleiben bytegenau erhalten. Nachweise:
`publish-all-final.log` und `publication-preservation-final.json`.

Die reMarkable-Desktop-App wurde mit dem endgültigen Ausgabeordner
abgeglichen: **74 von 74 aktive PDFs** sind bytegenau identisch und liegen
jeweils einmal am richtigen Zielort. Die 67 nicht betroffenen aktiven
Dokumente und alle 40 zuvor vorhandenen Archivdokumente behalten ihre
Identität, Ablageorte, PDFs und Anmerkungsbestände. Die fünf ersetzten
Originale bleiben unter `Archiv 2026-10-01 - Nulltransport` in ihren
jeweiligen Themenordnern erhalten; insgesamt gibt es jetzt 45 Archivdokumente.
Alle 13 Anmerkungsdateien der bisherigen Nullprodukt-Lesefassung sind
anhand ihrer individuellen Prüfsummen unverändert bestätigt. Der neue
Gesamtband wurde zusätzlich in der App geöffnet und mit 2742 Seiten angezeigt.

Nachweise stehen im [reMarkable-Bericht](remarkable-nulltransport-2026-10-01.md)
sowie in `tmp/remarkable-sync/comparison-anmerkungen-2026-10-01-phase2-nachher.json`
und `anmerkungen-2026-10-01-phase2-preservation.json`. Geprüft wurde der
Desktopbestand; ein unabhängiger Tablet-Test wurde nicht durchgeführt.
Bei den neuen mathematischen Ergänzungen wurden keine offenen
Beweislücken festgestellt.
Ausgangssicherungen, Seitenbilder und bisherige Nachweise liegen unter
[tmp/pdfs/nullproducts-annotations-2026-10-01](../tmp/pdfs/nullproducts-annotations-2026-10-01/).
