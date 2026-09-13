# Koinzidenz, Substitution und Korrektheit in Band 48

## Inhalt

Die bisherigen Skizzen zur Korrektheit wurden durch drei eingebundene
Abschnitte ergaenzt beziehungsweise ersetzt:

- `tex/b48/02-koinzidenz.tex`: Konstruktion der Freivariablenfunktion aus
  Baumrekursion, Belegungswechsel, Koinzidenz und Belegungsunabhaengigkeit von Saetzen.
- `tex/b48/02-substitution.tex`: syntaktische Variablenersetzung,
  die Bedingung "frei fuer", leere Ersetzungsstellen, Vertauschung von
  Belegungswechseln und die vollstaendige Fallunterscheidung am Binder.
- `tex/b48/02-korrektheit.tex`: semantische Folgerung unter offenen
  Annahmen, 21 elementare Regelfaelle und Induktion ueber die endliche Herleitung.

Der Satz `B48Soundness` behaelt seine stabile ID. Die neuen zentralen
IDs sind `B48Coincidence`, `B48SubstitutionLemma` und
`B48DerivationSoundness`. Die Beweisbilanz wurde entsprechend angepasst.

In Band 1 ist die Eigenvariablenbedingung der All-Einfuehrung
praezisiert: Die Variable darf in keiner offenen Annahme frei
vorkommen. Das Schema der klassischen Negationsbeseitigung zeigt nun
die Entladung der angenommenen Negation. Die Nebenbedingung
kollisionsfreier Einsetzungen ist ausdruecklich angegeben.

## Reichweite

Die Syntax- und Korrektheitsaussagen betreffen die konstantenfreie
Sprache mit Gleichheit und Elementrelation. Die einzigen Terme
dieser Sprache sind Variablen. Freie und gebundene Vorkommen werden
auf den bereits vorhandenen Baumcodes unterschieden.

Annahmen werden an ihren Zeilenindizes entladen; gleiche Formeln
an verschiedenen Annahmezeilen werden dadurch nicht verwechselt.
`Prf_1` liest elementare Herleitungen mit bereits aufgeloesten
Kurznotationen. Der Satz zertifiziert keine beliebigen
Bibliotheksverweise ohne zugehoerige Herleitung.

Die Henkin-Sprache mit neuen Konstanten, die dafuer benoetigten
Beweisumformungen und die Henkin-Vollstaendigkeit bleiben offen.
Die spaeteren Unabhaengigkeitsresultate erben diese noch offenen Voraussetzungen.

## Pruefung

Die gezielten endlichen Modellpruefungen behandeln 616 Formeln in
18 Strukturen mit einem oder zwei Elementen. Geprueft wurden
186192 Koinzidenzinstanzen, 684970 zulaessige Substitutionsinstanzen,
leere Ersetzungen und die Belegungswechsel. Hinzu kommen konkrete
Gegenbeispiele gegen Variablenfang und gegen All-Einfuehrung unter
einer offenen Annahme mit freier Eigenvariable.

Die Quellenpruefung umfasst 576 Beweiszeilen und kontrolliert
lokale B48-IDs, fruehere Zeilenverweise und die Verwendung von
Annahmenindizes. Diese Kontrollen und der LaTeX-Build sind keine
maschinelle Zertifizierung der mathematischen Beweise.

Als fachlicher Vergleich dienten die Abschnitte 16.5 und 16.6 des
[Open Logic Text](https://builds.openlogicproject.org/open-logic-complete.pdf)
ueber freie Variablen und Substitution. Die Ausarbeitung hier benutzt
die eigenen Baumcodes, Belegungsfunktionen und Beweistabellen des Projekts.
