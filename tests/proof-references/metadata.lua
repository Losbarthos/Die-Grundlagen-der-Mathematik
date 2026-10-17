-- Isolated registry regression; no TeX compilation or manuscript artifacts.
-- Run from the repository root:
--   texlua tests/proof-references/metadata.lua [OUTPUT_DIR] [MODULE_PATH]
local output = (arg[1] or 'tmp/proof-references-tests/metadata'):gsub('\\', '/')
local module_path = arg[2] or 'tex/impl/thmlookup.lua'
local lfs = require('lfs')
local function mkdirs(path)
  path = path:gsub('/+$', '')
  if lfs.attributes(path, 'mode') == 'directory' then return end
  local parent = path:match('^(.*)/[^/]+$')
  if parent and parent ~= '' then mkdirs(parent) end
  assert(lfs.mkdir(path))
end
mkdirs(output)
local base = output:gsub('/+$', '') .. '/'
local emitted
tex = {
  jobname = 'metadata-test',
  error = function(message) error(message) end,
  sprint = function(value) emitted = value end,
}
texio = {write_nl = function(message) print(message) end}
local M = dofile(module_path)

local function equal(actual, expected, context)
  assert(actual == expected, context .. ': expected ' .. string.format('%q', expected)
    .. ', got ' .. string.format('%q', actual))
end
local function fresh(path)
  M.registry_path = base .. path
  M.debug_path = base .. 'debug.log'
  M.reset_files()
end
local function metadata(label, number, display, delta)
  M.set_statement(label, 'theorem', number, display, delta)
  M.register(label, 'theorem', number, 'P \\rightarrow Q', 'Test title')
  M.register_id('Shared', 'theorem', label)
end
local function expect_reference(number)
  M.ref_by_structure('', 'P \\rightarrow Q', false)
  equal(emitted, '\\ThmLookupEmitRefResolved{theorem}{shared-label}{' .. number .. '}',
    'structural reference source priority')
end

-- Literal TeX escapes must not turn into control characters; actual control
-- characters and a literal backslash followed by n must also roundtrip.
local display = '\\neg P, \\triangleright Q \\vdash P \\land Q\nline\tcolumn\rreturn\\\\end\\n'
local delta = '\\DeltaRow{Variable}{x}[\\FormulaRefAuto{\\neg x}]\n\\DeltaRow{Variable}{y}'
fresh('roundtrip.tsv')
metadata('roundtrip', '1.2.3', display, delta)
M.set_statement('pure-id', 'definition', '4.5.6', '\\triangleright x \\coloneqq \\neg x', delta)
M.register_id('Pure', 'definition', 'pure-id')
equal(M.by_id.Pure.number, '4.5.6', 'fresh pure ID number')
M.by_key, M.by_id, M.by_label = {}, {}, {}
M.load_registry()
equal(M.by_label.roundtrip.display, display, 'exact display roundtrip')
equal(M.by_label.roundtrip.delta, delta, 'exact Delta roundtrip')
equal(M.by_label['pure-id'].display, '\\triangleright x \\coloneqq \\neg x', 'pure ID display')
equal(M.by_id.Pure.number, '4.5.6', 'loaded pure ID number')
assert(M.by_label.roundtrip.loaded and M.by_label.roundtrip.self_loaded)
M.set_statement('ghost', 'theorem', '9', 'ghost', '')
M.prepare_run()
assert(M.by_label.ghost == nil, 'prepare_run retained stale metadata')
equal(M.by_label.roundtrip.display, display, 'prepare_run lost self metadata')

fresh('external.tsv')
metadata('shared-label', '1', 'EXTERNAL', '')
fresh('self.tsv')
metadata('shared-label', '2', 'SELF', '')
M.by_key, M.by_id, M.by_label = {}, {}, {}
M.load_registry_file(base .. 'external.tsv')
equal(M.by_label['shared-label'].display, 'EXTERNAL', 'external load')
expect_reference('1')
M.load_registry()
equal(M.by_label['shared-label'].display, 'SELF', 'self beats prior external')
equal(M.by_id.Shared.number, '2', 'self ID beats prior external')
expect_reference('2')
M.load_registry_file(base .. 'external.tsv')
equal(M.by_label['shared-label'].display, 'SELF', 'later external cannot overwrite self')
equal(M.by_id.Shared.number, '2', 'later external ID cannot overwrite self')
expect_reference('2')
metadata('shared-label', '3', 'FRESH', '')
M.load_registry()
M.load_registry_file(base .. 'external.tsv')
equal(M.by_label['shared-label'].display, 'FRESH', 'fresh metadata wins')
equal(M.by_id.Shared.number, '3', 'fresh ID wins')
expect_reference('3')

local legacy = assert(io.open(base .. 'legacy.tsv', 'w'))
legacy:write('ID\tLegacy\ttheorem\tlegacy-label\n'
  .. '1\tlegacy-label\ttheorem\t7\tlegacy-key\tV1 vdash V2\tLegacy title\n')
legacy:close()
fresh('legacy-run.tsv')
M.load_registry_file(base .. 'legacy.tsv')
equal(M.by_label['legacy-label'].display, '', 'legacy canon is never display')
equal(M.by_id.Legacy.number, '7', 'legacy ID preceding structure has number')
M.register('manual', 'theorem', '8', 'ManualSymbolicKey', '')
equal(M.by_label.manual.display, '', 'manual key is never display')
M.reset_files()
assert(next(M.by_label) == nil, 'reset_files retained metadata')
print('PASS metadata: exact statements, pure IDs, source priority, legacy rows and lifecycle')
