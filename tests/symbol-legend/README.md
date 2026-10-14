# Page-local symbol legend fixtures

Run `python scripts/check-symbol-legend.py` from the repository. The checker
builds isolated LuaLaTeX documents into `tmp/symbol-legend-tests/`; it never
loads `main.tex`, rewrites a canonical registry or publishes a PDF.

The local fixture labels are synthetic test definitions, not manuscript
references. The core fixture imports the real `tabproof` environment so that
its nested boxes and ordinary tables are both exercised. Expected entries are
checked against both the Lua audit and the rendered PDF text. PDF links and
two-sided placement are checked independently. A disabled build is compared
with a document that does not load the legend module at all.

Introduction is page-based: a symbol introduced anywhere on a shipped page
may occur in that page's legend. Earlier pages remain unintroduced; later
pages still need an actual use. Discarded measurement boxes and unchosen
mathchoice branches do not introduce or use a symbol.

Overflow and invalid-reference fixtures must fail explicitly rather than
produce an apparently successful document with lost entries.
An ordinary local label may be unresolved during the first pass; it must be
resolved during the second. The permanently missing-label case succeeds only
when the final checker detects its warning and visible question marks.
Leader fixtures retain their glue between printed words: TeX would otherwise
discard trailing glue before shipout and correctly leave no marker to reject.

For local reading introductions, declare
`\SymbolLegendDeclareReading{id}{symbol display}{meaning}`. Put
`\SymbolLegendIntroduce{id}\SymbolLegendUse{id}` inside the same visible
math atom at the explanation, and only `\SymbolLegendUse{id}` at later uses.
The first retained introduction receives the reserved PDF destination and
label `slreading:id`. Entries read `Einführung, S. N`; they do not invent a
definition number. The label is installed at actual shipout and written to
the AUX file, including roman page numbering. Repeated or copied introduction
markers share the first destination. Disabled or suppressed recording creates
neither a label nor a destination. Legacy `Declare`/`DeclareID` entries retain
their existing definition-reference format.

Optional `\SymbolLegendCompacttrue` places the symbol and meaning in one
paragraph, retains the introduction/definition link on a separate line, and
uses 4 pt entry spacing. It preserves the 9/11 pt font and both overflow
checks. The default remains the original three-line layout with 7 pt spacing.
`reading-compact` runs the full local-link fixture in this mode and checks
that the symbol/meaning share a line while the link stays below it.

`reading-links` verifies destinations at the actual introduction lines,
same-page and later links, a box moved by a real page break, discarded boxes
and pages, selected mathchoice branches, repeated introductions, and roman
page labels. `color-state` renders two otherwise identical legends, once at
black shipout and once at white shipout. Each legend word must contain black
ink and the entire legend must be pixel-identical; the white body must stay
white. The color test additionally requires `pdftoppm` and Pillow.

Run the focused regression set with:
`python scripts/check-symbol-legend.py --case reading-links --case color-state --case core --case twoside --case disabled --case baseline`.


The complete legend entry is now one fixed-width hyperlink box. Tests inspect
its actual PDF annotation, the symbol and explanation ink, the full page
reference, and separation from neighboring tap areas. Font-box overhangs are
checked against rendered ink instead of accepting a looser boundary.

Published reading legends use explicit page-reference `/Fit` destinations;
this conversion is covered separately by
`python tests/test_publish_reading_links.py`. It resolves page references
after cloning, retains named destinations, and leaves unrelated links intact.
