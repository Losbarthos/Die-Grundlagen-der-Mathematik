# Überarbeitung von Band 28 und seinen Grundlagen

## Beweisformatierung in Band 28

Ausgelagerte Begründungen beginnen am Formelrand. Ungebrochene Zeilen erhalten
einen festen Mindestabstand zwischen Formel und Begründung. Diese Einstellung
gilt nur in Band 28 und wird am Bandende zurückgesetzt. Insbesondere stehen die
Assoziativitätsverweise bei der Minimums- und Maximumshalbgruppe wieder in der
gemeinsamen Begründungsspalte.

## Induktion mit Addition

Band 10 führt unmittelbar nach den rekursiven Grundlagen der Addition die
Schnittstelle für `n + 1` ein. Die zentralen stabilen Resultat-IDs sind:

| Resultat | Verwendung |
| --- | --- |
| `PeanoInductionAddOne`, `PeanoInductionRuleAddOne` | Induktion mit Anfang 0 und Schritt von n auf n + 1. |
| `PeanoInductionFromOne`, `PeanoInductionRuleFromOne` | Induktion über positive natürliche Zahlen mit Anfang 1. |
| `PeanoInductionFromBase`, `PeanoInductionRuleFromBase` | Induktion ab einem beliebigen natürlichen m; nach der benötigten Ordnungscharakterisierung. |
| `PeanoAddOneClosure`, `PeanoAddOneNonzero`, `PeanoAddOneInjective` | Grundlegende Nachfolgereigenschaften in Additionsschreibweise. |
| `PeanoNonzeroIsAddOne` | Darstellung einer positiven natürlichen Zahl als k + 1. |
| `PeanoRecursionAddOne`, `DedekindRecursionTheoremAddOne` | Rekursionsgleichung und eindeutig bestimmte Rekursionsfunktion mit n + 1. |

Die zugehörigen Satznummern sind 10.4.4.14/15 (Anfang 0), 10.4.4.16/17
(Anfang 1) und 10.4.5.7/8 (beliebiger Anfang m). Die grundlegenden
Nachfolgereigenschaften in Additionsschreibweise stehen ab 10.4.4.7.

Die späteren natürlichen Induktionsanwendungen in den aktiven Bänden verwenden
diese Theoreme. Die Potenzinduktionen in Band 28 beginnen unmittelbar bei 1;
der Rückweg über `succ(pred(n))` entfällt. Die Wortinduktion in Band 27 beginnt
ebenfalls bei Wortlänge 1, die Baumstufen verwenden durchgängig den Index n + 1.

Die vor Einführung der Addition benötigten Induktions- und Rekursionsbeweise
bleiben auf den Nachfolger gestützt. Wo ältere mengen- oder
rekursionstheoretische Hilfssätze noch Nachfolgerterme enthalten, wird der
Übergang zu n + 1 ausdrücklich durch Gleichheitselimination begründet.
Bestehende Formelschlüssel bleiben teilweise als äquivalente Nachfolgerform
registriert, damit externe Referenzen weiterhin eindeutig auflösbar sind.

## Axiomatische Strukturbegriffe

Unterhalbgruppen, Links- und Rechtsideale sowie zweiseitige Ideale erhalten
getrennte Strukturbedingungen und Zugriffaxiome. Die bisherigen
Konjunktionsbedingungen werden als Kriterien bewiesen. Redundante
Zugriffstheoreme mit genau derselben Aussage wie ein neues Axiom entfallen;
ihre Verbraucher zitieren unmittelbar das Axiom.

Die entsprechende Durchsicht umfasst außerdem Dedekindschnitte, gerichtete
Walks/Pfade/Kreise und Azyklizität, die Baumhierarchie, volle endliche
Präfixmengen, spezialisierte Homomorphismen und Isomorphismen sowie Metriken.
Konstruktionen von Mengen und Funktionen bleiben Definitionen. Die
Charakterisierungsbeweise sichern die bisherigen Bedingungen in beiden
Richtungen.

## Direkte Verwendung von Iota-Definitionen

`IotaEvaluation` (ehemals Theorem 2.10.9.7) wurde ersatzlos entfernt. Seine
Verbraucher in Band 10 und Band 27 verwenden unmittelbar die jeweilige
Iota-Definition. Unnötige Gleichheitszeilen wurden entfernt und die folgenden
Zeilenverweise einschließlich gemeinsam verwendeter Beweismakros angepasst.

## Prüfung

Die geänderten Induktions- und Charakterisierungsbeweise wurden unabhängig
gegengelesen. Dabei wurden auch fehlerhafte ältere Zeilenverweise,
Implikationsregeln, Pfadprojektionen und Fallunterscheidungen in unmittelbar
betroffenen Beweisen korrigiert.

Die technischen Build- und PDF-Prüfungen verwenden die vorhandenen Skripte
`scripts/build-all.ps1`, `scripts/audit-build.ps1` und
`scripts/publish-pdfs.py`. Sie kontrollieren Resultatregister, Querverweise,
PDF-Ziele und die Übereinstimmung von Einzelbänden und Gesamtband.

Die Abschlussprüfung vom 3. September 2026 ist bestanden:

- Alle geänderten Einzelbände, die reMarkable-Fassung und der Gesamtband bauen erfolgreich.
- Resultatregister und Satznummern der Einzelbände stimmen mit dem Gesamtband überein.
- Die vollständige Ausgabe in `output/pdf` enthält 45 PDFs mit insgesamt 4.115 Seiten.
  Der Linktest bestätigt 48.411 interne und 27.274 bandübergreifende Links.
- Band 28 umfasst 129 Seiten und erzeugt weder einzeln noch im Gesamtband
  Overfull-Warnungen. Die Beispielstelle 28.2.5.1, die positiven
  Potenzinduktionen, die Unterhalbgruppenaxiome und die Hauptidealbeweise
  wurden zusätzlich an gerenderten PDF-Seiten geprüft.
- Die neuen Induktionssätze in Band 10 sowie die Iota-Schritte, Wortinduktion
  und Präfixmengen in Band 27 wurden ebenfalls visuell kontrolliert.
- `git diff --check` ist sauber; in den Bandquellen verbleiben keine Verweise
  auf `IotaEvaluation` oder die alte Nummer 2.10.9.7.
