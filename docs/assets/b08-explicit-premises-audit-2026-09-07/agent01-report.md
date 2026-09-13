# B08: Voraussetzungenprüfung des Anfangs- und Kompositionsbereichs

Prüfstand: 7. September 2026. Erfasst wurden alle Aussagen, Delta-Kontexte und zugehörigen Beweistabellen vom Bandanfang bis vor „Umkehrfunktion“ sowie „Kompositionen und Inversen“ bis vor „Induzierte Potenzmengenabbildung“. Das sind 36 Haupttheoreme und 6 registrierte Hilfssätze. Die unveränderte erste Lesefassung mit vollständigen Formeln, Strukturkeys, Delta-Kontexten und Beweisen ist in `agent01-inventory.json` dokumentiert.

`ok` bezeichnet hier eine hinsichtlich ihrer sachlichen Voraussetzungen vollständige Aussage, keine pauschale Bestätigung sämtlicher alten Beweisschritte. `change` bezeichnet eine im ersten Prüfstand unvollständige Sequenz; die nachstehend genannten 15 Sequenzen wurden inzwischen korrigiert.

## Vollständige Haupttheoremliste

| Theorem | Aussage | Entscheidung |
|---|---|---|
| 8.2.1.1 | Subbeweiseinsetzung für bijektive Funktionen | ok |
| 8.2.1.2 | Wert liegt im Zielbereich | ok |
| 8.2.1.3 | Bildzugehörigkeit einer Teilmenge | ok |
| 8.2.1.4 | Injektivität und Surjektivität ergeben Bijektivität | ok; redundanten DeltaPrem entfernt und Beweis getypt |
| 8.2.1.5 | Bijektiv impliziert injektiv | ok |
| 8.2.1.6 | Bijektiv impliziert surjektiv | ok |
| 8.2.1.7 | Äquivalentes Bijektivitätskriterium | ok |
| 8.2.1.8 | Eindeutiges Urbild | ok |
| 8.2.1.9 | Urbildmenge liegt im Definitionsbereich | ok |
| 8.2.2.1 | Vollständiges Bild | ok |
| 8.3.1.1 | Identität ist Funktion | ok |
| 8.3.1.2 | Identität ist totale Relation | ok |
| 8.3.1.3 | Wert der Identität | ok |
| 8.3.1.4 | Umgekehrte Identitätsgleichung | ok |
| 8.3.1.5 | Injektivitätskriterium der Identität | ok |
| 8.3.1.6 | Surjektivitätskriterium der Identität | ok |
| 8.3.1.7 | Bijektivität der Identität | ok |
| 8.3.2.1 | Bijektive Einschränkung auf ein Urbild | ok |
| 8.3.2.2 | Punktweises Kriterium für bijektive Einschränkungen | ok |
| 8.3.2.3 | Bijektive Korestriktion auf das Bild | ok |
| 8.3.4.1 | Bijektivität der Komposition | ok; redundanten DeltaPrem entfernt und Beweis getypt |
| 8.3.4.2 | Linksneutralität | change; explizite Prämissen und neuer Beweis umgesetzt |
| 8.3.4.3 | Rechtsneutralität | change; explizite Prämissen und neuer Beweis umgesetzt |
| 8.3.4.4 | F nach seiner Inversen | change; explizite Prämissen und neuer Beweis umgesetzt |
| 8.3.4.5 | Inverse nach F | change; explizite Prämissen und neuer Beweis umgesetzt |
| 8.3.4.6 | Punktweise Linksumkehrung einer Komposition | change; explizite Prämissen und neuer Beweis umgesetzt |
| 8.3.4.7 | Inverse der Komposition | change; explizite Prämissen und neuer Beweis umgesetzt |
| 8.3.4.8 | Innerer Faktor: Injektivitätskriterium | change; explizite Prämissen und neuer Beweis umgesetzt |
| 8.3.4.9 | Äußerer Faktor: Surjektivitätskriterium | change; explizite Prämissen und neuer Beweis umgesetzt |
| 8.3.4.10 | Äußerer Faktor: Injektivitätskriterium bei surjektivem F | change; explizite Prämissen und neuer Beweis umgesetzt |
| 8.3.4.11 | Innerer Faktor injektiv | change; explizite Prämissen und neuer Beweis umgesetzt |
| 8.3.4.12 | Äußerer Faktor surjektiv | change; explizite Prämissen und neuer Beweis umgesetzt |
| 8.3.4.13 | Äußerer Faktor bijektiv bei surjektivem F | change; explizite Prämissen und neuer Beweis umgesetzt |
| 8.3.4.14 | F bijektiv bei beidseitiger Umkehrung | change; explizite Prämissen und neuer Beweis umgesetzt |
| 8.3.4.15 | G bijektiv bei beidseitiger Umkehrung | change; explizite Prämissen und neuer Beweis umgesetzt |
| 8.3.4.16 | G ist die Umkehrfunktion von F | change; explizite Prämissen und neuer Beweis umgesetzt |

## Vollständige Liste der registrierten Hilfssätze

| Hilfssatz | Schlüssel / Aussage | Entscheidung |
|---|---|---|
| 8.2.2.1(H1) | `F\colon A\bij B \vdash F[A]\subseteq B` | ok: sämtliche sachlichen Voraussetzungen stehen ausdrücklich in der Sequenz |
| 8.2.2.1(H2) | `F\colon A\bij B \vdash B\subseteq F[A]` | ok: sämtliche sachlichen Voraussetzungen stehen ausdrücklich in der Sequenz |
| 8.3.2.2(H1) | `BijectiveRestrictionSubsetMembershipImpliesTargetMembership` | ok: sämtliche sachlichen Voraussetzungen stehen ausdrücklich in der Sequenz |
| 8.3.2.2(H2) | `BijectiveRestrictionTargetMembershipImpliesSubsetMembership` | ok: sämtliche sachlichen Voraussetzungen stehen ausdrücklich in der Sequenz |
| 8.3.2.2(H3) | `BijectiveRestrictionImpliesPointwiseCompatibility` | ok: sämtliche sachlichen Voraussetzungen stehen ausdrücklich in der Sequenz |
| 8.3.2.2(H4) | `PointwiseCompatibilityImpliesBijectiveRestriction` | ok: sämtliche sachlichen Voraussetzungen stehen ausdrücklich in der Sequenz |

## Sachliche Annahmen, Sorten und Notation

`DeltaRow{Mengen}{A,B,...}` sowie bloße Funktionsvariablen F/G sind Sortenangaben. Die Identität wird durch `IdentityFunctionDef` für jede Menge A eingeführt; ihre Funktionseigenschaft ist kein zusätzlich zu verlangender Sachverhalt. Für die Identitätssätze wurde deshalb weder Nichtleerheit noch eine künstliche Prämisse `Id_A:A→A` hinzugefügt. Auch bei den Einschränkungs- und Urbildsätzen stehen die Bijektivität, Teilmengenbeziehungen und Elementzugehörigkeiten bereits in der Aussage.

Dagegen sind Angaben wie `F:A→B`, `F:A≅B` oder `G∘F:A≅C` echte sachliche Voraussetzungen. In den 15 Kompositionsfolgen standen sie teilweise ausschließlich im Delta-Kontext. Sie werden nun in der Sequenz und als nummerierte Annahmen geführt. Ein schon vorhandenes `F:A↣B`, `F:A↠B` oder `F:A≅B` erlaubt dagegen, `F:A→B` herzuleiten; eine zweite unabhängige Typprämisse wurde in diesen Fällen nicht erfunden.

## Umgesetzte explizite Sequenzen und neue IDs

### 8.3.4.1 — `BijectiveFunctionComposition`

```tex
F\colon A\bij B \dsep G\colon B\bij C\vdash G\circ F\colon A\bij C
```

### 8.3.4.2 — `FunctionLeftIdentity`

```tex
F\colon A\to B\vdash \Id_B\circ F=F
```

### 8.3.4.3 — `FunctionRightIdentity`

```tex
F\colon A\to B\vdash F\circ\Id_A=F
```

### 8.3.4.4 — `InverseFunctionRightComposition`

```tex
F\colon A\bij B\vdash F\circ F^{-1}=\Id_B
```

### 8.3.4.5 — `InverseFunctionLeftComposition`

```tex
F\colon A\bij B\vdash F^{-1}\circ F=\Id_A
```

### 8.3.4.6 — `InverseCompositionLeftInversePointwise`

```tex
\begin{aligned}[t]
  &G\colon A\bij B\dsep F\colon B\bij C\dsep x\in A\vdash{}\\[-2pt]
  & (G^{-1}\circ F^{-1})\bigl((F\circ G)(x)\bigr)=x
\end{aligned}
```

### 8.3.4.7 — `InverseFunctionComposition`

```tex
G\colon A\bij B\dsep F\colon B\bij C\vdash G^{-1}\circ F^{-1}=(F\circ G)^{-1}
```

### 8.3.4.8 — `BijectiveCompositionInnerInjectiveCriterion`

```tex
\begin{aligned}[t]
  &F\colon A\to B\dsep G\colon B\to C\dsep{}\\[-2pt]
  & G\circ F\colon A\bij C\dsep x\in A\dsep y\in A\dsep F(x)=F(y)\vdash{}\\[-2pt]
  & x=y
\end{aligned}
```

### 8.3.4.9 — `BijectiveCompositionOuterSurjectiveCriterion`

```tex
\begin{aligned}[t]
  &F\colon A\to B\dsep G\colon B\to C\dsep{}\\[-2pt]
  & G\circ F\colon A\bij C\dsep y\in C\vdash{}\\[-2pt]
  & \exists x\in B\;G(x)=y
\end{aligned}
```

### 8.3.4.10 — `BijectiveCompositionOuterInjectiveCriterion`

```tex
\begin{aligned}[t]
  &F\colon A\sur B\dsep G\colon B\to C\dsep{}\\[-2pt]
  & G\circ F\colon A\bij C\dsep x\in B\dsep y\in B\dsep G(x)=G(y)\vdash{}\\[-2pt]
  & x=y
\end{aligned}
```

### 8.3.4.11 — `BijectiveCompositionInnerInjective`

```tex
\begin{aligned}[t]
  &F\colon A\to B\dsep G\colon B\to C\dsep G\circ F\colon A\bij C\vdash{}\\[-2pt]
  & F\colon A\inj B
\end{aligned}
```

### 8.3.4.12 — `BijectiveCompositionOuterSurjective`

```tex
\begin{aligned}[t]
  &F\colon A\to B\dsep G\colon B\to C\dsep G\circ F\colon A\bij C\vdash{}\\[-2pt]
  & G\colon B\sur C
\end{aligned}
```

### 8.3.4.13 — `BijectiveCompositionOuterBijective`

```tex
\begin{aligned}[t]
  &F\colon A\sur B\dsep G\colon B\to C\dsep G\circ F\colon A\bij C\vdash{}\\[-2pt]
  & G\colon B\bij C
\end{aligned}
```

### 8.3.4.14 — `MutuallyInverseFunctionBijection`

```tex
\begin{aligned}[t]
  &G\colon A\to B\dsep F\colon B\to A\dsep{}\\[-2pt]
  & F\circ G=\Id_A\dsep G\circ F=\Id_B\vdash{}\\[-2pt]
  & F\colon B\bij A
\end{aligned}
```

### 8.3.4.15 — `MutuallyInverseCompanionBijection`

```tex
\begin{aligned}[t]
  &G\colon A\to B\dsep F\colon B\to A\dsep{}\\[-2pt]
  & F\circ G=\Id_A\dsep G\circ F=\Id_B\vdash{}\\[-2pt]
  & G\colon A\bij B
\end{aligned}
```

### 8.3.4.16 — `MutuallyInverseFunctionEquality`

```tex
\begin{aligned}[t]
  &G\colon A\to B\dsep F\colon B\to A\dsep{}\\[-2pt]
  & F\circ G=\Id_A\dsep G\circ F=\Id_B\vdash{}\\[-2pt]
  & G=F^{-1}
\end{aligned}
```

Die drei Komponentenkriterien 8.3.4.8–10 besitzen jetzt vollständige Typ- und Bijektivitätsprämissen auch in der sichtbaren Aussage. Für 8.3.4.14–16 gilt verbindlich die Reihenfolge `G:A→B`, `F:B→A`, `F∘G=Id_A`, `G∘F=Id_B`. Alte unterprämisierte Strukturformeln wurden nicht als Aliase registriert. `BijectiveFunctionComposition` bleibt als bestehende ID erhalten. Die Haupttheoremzahl und damit ihre Nummern bleiben erhalten.

## Beweise und Validierung

Der Kompositionsabschnitt wurde mit 242 nummerierten Schritten neu hergeleitet. Die beiden Funktionsprämissen gehen ausdrücklich in `CompositionDef` ein; Wertgleichungen werden zunächst universal gewonnen und dann an einer ausgewiesenen Elementzugehörigkeit instanziiert. Surjektivitätsargumente führen getypte Zeugen ein und entlassen jede Zeugenannahme durch ∃E. Injektivitätskriterien werden mit einzelnen Annahmen und →I/∀I geschlossen. Extensionalität erhält beide Funktionstypen und die tatsächliche punktweise Gleichheit.

Der bisherige Beweis von 8.3.4.7 zitierte Rechtsinversen-Eindeutigkeit nach einer linken Inversengleichung. Der neue Beweis setzt in der linken Gleichung `x=(F∘G)^{-1}(y)` ein und benutzt die Rechtsinversengleichung der bereits typisierten Bijektion `F∘G`; daraus folgt die für Extensionalität benötigte Gleichheit. Die beidseitigen Kompositionskriterien transportieren Identitäts-Bijektivität erst nach ausdrücklich bewiesener Symmetrie der jeweiligen Kompositionsgleichung.

8.2.1.4 hat jetzt einen zusammenhängenden Beweis mit sechs Zeilen: zwei Annahmen; Funktionstyp und quantifiziertes Injektivitätskriterium aus der ersten; quantifiziertes Surjektivitätskriterium mit Abhängigkeit [2] aus der zweiten; Schluss `Bijektive Funktion[def]{3,4,5}`.

`tmp/b08-explicit-premises/composition-validation.json` bestätigt alle 242 lokalen Schrittverweise und berechneten Annahmenmengen, insbesondere die letzten Abhängigkeiten gleich den jeweiligen Sequenzprämissen. `composition-refcheck.lua` prüfte alle 14 verwendeten bereits vorhandenen Referenzkeys mit dem tatsächlichen Lua-Normalisierer erfolgreich. Die neuen Inversen-IDs werden mit dem parallel überarbeiteten Umkehrabschnitt verbunden. Ein Build wurde hier nicht gestartet; interne und externe Aufrufmigration sowie Gesamtprüfung koordiniert Root.

## Frühe Beweisbefunde und ihre anschließende Erledigung

In der ersten lesenden Prüfung waren folgende Begründungsdetails sichtbar, ohne dass dadurch zusätzliche sachliche Theoremprämissen nötig werden:

- 8.2.1.8 benötigt vor Anwendung des Injektivitätskriteriums einen expliziten Übergang von Bijektivität zu Injektivität; die Aussage selbst hat bereits F bijektiv als Prämisse.
- 8.2.2.1(H2) ruft den Surjektivitätszeugen im Ausgangstext nur mit der Elementzeile auf, obwohl die Surjektivität schon als eigene Zeile vorliegt; diese Zeile gehört zur Anwendung.
- 8.3.1.4 enthält zwei Theoremreferenzen ohne ihre vorhandenen Schrittargumente. 8.3.1.7 gewinnt die universalen Injektivitäts-/Surjektivitätsbedingungen unmittelbar aus den punktweisen Sequenzen; bei strenger Tabellenform sind dafür die angenommenen Element-/Gleichheitsbedingungen und ihre Entladung auszuführen.
- 8.3.2.1 führt an zwei Stellen Schlusszeilennummern statt ihrer Annahmen als Abhängigkeiten und benutzt für den Bijektivitätsschluss die Definition ohne ausdrücklich zugeführten Funktionstyp. Ein korrekt getypter Schluss kann auch den vorhandenen Inj+Sur→Bij-Satz verwenden.
- 8.3.2.2(H1) sollte bei der Auswertung der Einschränkung den aus der vorhandenen Bijektivität abgeleiteten Funktionstyp ausdrücklich mitführen. Auch hier ist die Theoremaussage bereits vollständig.

Diese sechs Detailbefunde wurden nach gesonderter Freigabe sämtlich behoben, ohne zusätzliche Theoremprämissen zu erfinden oder Aussagen und Hauptnummern zu ändern. Die sechs neuen Tabellen enthalten 70 Schritte; `tmp/b08-explicit-premises/early-proof-fixes-report.md` beschreibt jeden Schluss. Das vollständige Vorher-/Nachher-Ledger und die maschinelle Abhängigkeitsprüfung liegen daneben. Alle 13 darin verwendeten vorhandenen Referenzkeys sind mit dem tatsächlichen Lua-Normalisierer auflösbar. Agent15 bestätigte unabhängig die mathematischen Schritte.

Auch die fünf von Root erweiterten inneren Allquantorschlüsse wurden unabhängig über alle 88 aktuellen Schritte geprüft, einschließlich vollständiger Umnummerierung nach der jeweiligen Einfügestelle. Zwei zusätzlich konkret gefundene rückwärts eingesetzte Gleichheiten in `LayerPowerMapPreservesSubsetsBackward` und `FixedEmptyBijectionNonemptyPreimageForward` sind jetzt richtig orientiert; sie ändern keine Nummern. Die separate unabhängige Schlussprüfung der sechs frühen Tabellen und dieser beiden Teile umfasst 109 aktuelle Zeilen und hat keine offenen Befunde. Die Prüfberichte unterscheiden diese begrenzte Arbeit weiterhin von einer vollständigen Formalisierung aller Beweise des Bandes.
