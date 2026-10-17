# Automatic proof-reference integration fixtures

Run `python scripts/check-proof-references.py` from the repository root.
The checker needs LuaLaTeX, `pdftotext` and Python's `pypdf` and `pdfplumber`;
it builds each fixture twice.
PDFs, logs, independent registries and renderer observations stay under
`tmp/proof-references-tests/`. It does not load `main.tex` or modify the
manuscript's registries. `--output PATH` selects a different output directory.

`core.tex` exercises normal, wide, paired and split proof tables, nested
tables in one outer proof, numbered helper statements, forward references,
ID/structure aliases, duplicate references and the central on/off switch.
It checks first-use order, isolation between proofs, suppression of helper
headers and references inside the generated table, complete original Delta
contexts, and original multiline displays whose lookup keys differ.
It also covers classical definition/theorem/axiom environments with prose
premises and displayed formulas, referenced through explicitly registered IDs.
Proof steps inside a bare `longtable` must produce an overview as well;
an ordinary `longtable` containing references must not produce one.

`producer.tex` and `consumer.tex` test persistence across independent
documents, including original premises missing from the structural key and
reference numbers available without an imported `.aux` file.

`pagination.tex` references twenty statements with their full assumptions in
one proof. Its overview must span multiple pages, repeat the continuation
header and retain every entry exactly once.

`tall-context.tex` covers one statement whose forty-four multiline context
rows exceed one page. Its Delta context includes `DeltaDecl`, `DeltaPrem`,
notes, explicit `DeltaContext` block transitions and a raw three-column
heading, matching existing manuscript syntax. The single statement must
continue across pages without losing its premises, headings or conclusion.

`overflow.tex` registers original displays directly without printing a source
declaration. Its two sixty-term formulas must wrap onto multiple readable
lines. A seventy-two-line aligned statement and an equally tall single Delta
row must each continue across pages. Every content marker and indexed term
must appear exactly once; the final note, conclusion and following paragraph
must remain visible in order. PDF word rectangles verify glyph sizes, column
bounds and real page breaks, rejecting a whole-formula scaling workaround.

`table-tail.tex` drives the renderer directly at twenty-five different page
positions, placing a tall cases formula after twenty short rows. Every final
formula and following paragraph must survive exactly once. The checker reads
PDF marked-content operators on every table page: its first proof-reference
tag must be a header, so a final row that slips past the longtable output
routine onto a page without a continuation head cannot pass. Both cases,
the premise and the conclusion must remain together on the marker's page.

`graphics-state.tex` covers wide scaled and rotated statements with aligned
conclusions, a colored formula and normal statements immediately afterwards.
PDF operators must restore scaling/rotation, color and the q/Q stack
inside every marked table cell. Right-column references and following lines
must retain their normal size and position. The fixture records actual LuaTeX
graphics/link node subtypes and verifies every content marker. A seventy-two-line
Delta context with one locally closed hyperlink must still continue across
pages at normal size, preventing an unnecessarily broad graphics-state guard.
The full marked-content geometry audit additionally checks every formula,
reference and header object against its cell and page text area with a 0.5 pt
tolerance, so a rotated box cannot pass merely by restoring its PDF state.

The fixtures wrap the public `ProofReferenceEntry` renderer to record its
arguments while retaining the actual PDF output. The checker compares both
these observations and extracted PDF text; it also rejects unresolved
references, duplicate or misplaced headings, overfull lines or pages, and
missing glyphs.
For the long context, PDF word rectangles additionally verify that no formula
overlaps a row or block heading, including cases that produce no TeX warning.
All fixtures also require a visible table title before the first marked cell
on every table page.
