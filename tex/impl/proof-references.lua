-- Proof-local references. Statement text is owned by thmlookup, not by the
-- lookup query (which may be an ID or an alpha-normalized structure).
local M = { depth = 0, entries = {}, seen = {} }

-- Mark the actual shipped cells for the PDF geometry audit. Coordinates in
-- PRBounds use PDF points and a top-left origin, matching pdfplumber. Reading
-- pdf.getpos here (from a late_lua node) also handles moved longtable rows.
function M.begin_cell(tag, width, top, bottom, odd_left, even_left, text_width)
  local sp_to_bp = 72 / (72.27 * 65536)
  local left = pdf.getpos() * sp_to_bp
  local text_left = (tex.count[0] % 2 == 1 and odd_left or even_left) * sp_to_bp
  pdf.print('page', string.format(
    '\n/%s << /PRBounds [%.5f %.5f %.5f %.5f] /PRTextBounds [%.5f %.5f %.5f %.5f] >> BDC\n',
    tag, left, top * sp_to_bp, left + width * sp_to_bp, bottom * sp_to_bp,
    text_left, top * sp_to_bp, text_left + text_width * sp_to_bp, bottom * sp_to_bp))
end

function M.end_cell()
  pdf.print('page', '\nEMC\n')
end

function M.begin_proof()
  if M.depth == 0 then M.entries, M.seen = {}, {} end
  M.depth = M.depth + 1
end

-- A few manuscript proofs use a bare longtable with the common step macros.
-- Start lazily on their first step, so ordinary reference tables stay untouched.
function M.ensure_proof()
  if M.depth == 0 then
    M.begin_proof()
    M.implicit_table = true
  end
end

function M.end_table(enabled)
  if M.implicit_table then
    M.implicit_table = false
    M.end_proof(enabled)
  end
end

function M.record(label)
  if M.depth == 0 or M.seen[label] then return end
  local r = thmlookup and thmlookup.by_label and thmlookup.by_label[label]
  if not r then return end -- ordinary section/equation labels are not results
  M.seen[label] = true
  M.entries[#M.entries + 1] = label
end

-- Delta bodies in the manuscript contain rows, split DeltaContext blocks and
-- a few three-column headings. Decode only their outer structure; the formula,
-- labels and notes inside each balanced argument remain unchanged.
local function delta_rows(source)
  local rows, position = {}, 1
  local function skip_space()
    local _, last = source:find('^%s*', position)
    position = (last or position - 1) + 1
  end
  local function command_at(index)
    if source:sub(index, index) ~= '\\' then return nil end
    local name = source:match('^\\([A-Za-z@]+)', index)
    if name then return name, index + #name + 1 end
    return source:sub(index + 1, index + 1), index + 2
  end
  local function argument(opener, optional)
    skip_space()
    if source:sub(position, position) ~= opener then
      if optional then return '' end
      error('expected ' .. opener .. ' at character ' .. position, 0)
    end
    local closer = opener == '{' and '}' or ']'
    local start, depth, braces = position + 1, 1, 0
    position = start
    while position <= #source do
      local char = source:sub(position, position)
      if char == '\\' then
        local _, following = command_at(position)
        position = following
      else
        if opener == '[' then
          if char == '{' then braces = braces + 1 end
          if char == '}' then braces = braces - 1 end
        end
        if braces == 0 then
          if char == opener then depth = depth + 1 end
          if char == closer then depth = depth - 1 end
          if depth == 0 then
            local value = source:sub(start, position - 1)
            position = position + 1
            return value
          end
        end
        position = position + 1
      end
    end
    error('unclosed ' .. opener .. ' argument at character ' .. (start - 1), 0)
  end
  local function parse()
    while true do
      skip_space()
      if position > #source then return rows end
      local name, following = command_at(position)
      if not name then error('unexpected text at character ' .. position, 0) end
      position = following
      if name == 'DeltaRow' or name == 'DeltaDecl' or name == 'DeltaPrem' then
        local title, formula = argument('{'), argument('{')
        local note = argument('[', true)
        if name == 'DeltaPrem' then formula = '\\triangleright\\,' .. formula end
        if not formula:match('%S') and not note:match('%S') then
          rows[#rows + 1] = {kind = 'heading', title = title}
        else
          rows[#rows + 1] = {kind = 'row', title = title, formula = formula, note = note}
        end
      elseif name == 'begin' or name == 'end' then
        local environment = argument('{')
        if environment ~= 'DeltaContext' then
          error('unsupported environment ' .. environment, 0)
        end
        if name == 'begin' then
          local title = argument('{')
          if title:match('%S') then rows[#rows + 1] = {kind = 'heading', title = title} end
        end
      elseif name == 'multicolumn' then
        local columns = argument('{')
        if not columns:match('^%s*3%s*$') then
          error('expected a three-column Delta heading, got ' .. columns, 0)
        end
        argument('{') -- Original Delta table alignment is irrelevant here.
        rows[#rows + 1] = {kind = 'heading', title = argument('{')}
        skip_space()
        local separator, after_separator = command_at(position)
        if separator ~= '\\' then error('Delta heading has no row terminator', 0) end
        position = after_separator
        skip_space()
        if source:sub(position, position) == '*' then position = position + 1 end
        argument('[', true) -- Original compact-table spacing is not replayed.
      elseif name == 'par' then
        -- Blank source lines become explicit paragraph tokens on detokenizing.
        -- They only separate the outer Delta rows and carry no premise text.
      else
        error('unsupported Delta command \\' .. name .. ' at character ' .. position, 0)
      end
    end
  end
  local success, result = pcall(parse)
  if success then return result end
  return nil, result
end

function M.emit_entry(display, delta, env, label, number)
  local context, problem = delta_rows(delta or '')
  if not context then
    texio.write_nl('proof-references ERROR: ' .. label .. ': ' .. tostring(problem))
    tex.error('ProofReferences: cannot render Delta context for ' .. label, {
      tostring(problem),
      'The complete original context remains in the registry; it was not discarded.',
    })
    return
  end
  local link = '\\ProofReferenceLink{' .. env .. '}{' .. label .. '}{' .. number .. '}'
  local rendered = {}
  for _, row in ipairs(context) do
    -- Each atomic row can start a continuation page. Repeat its source so a
    -- middle page of a large definition never loses the statement identity.
    local reference = link
    if row.kind == 'heading' then
      rendered[#rendered + 1] = '\\ProofReferenceContextHeading{' .. row.title .. '}{' .. reference .. '}'
    else
      rendered[#rendered + 1] = '\\ProofReferenceContextRow{' .. row.title .. '}{' ..
        row.formula .. '}{' .. row.note .. '}{' .. reference .. '}'
    end
  end
  rendered[#rendered + 1] = '\\ProofReferenceFormulaRow{' .. display .. '}{' .. link .. '}'
  tex.sprint(table.concat(rendered, ' '))
end

function M.end_proof(enabled)
  if M.depth == 0 then return end
  M.depth = M.depth - 1
  if M.depth > 0 or #M.entries == 0 then return end
  if enabled == false then M.entries, M.seen = {}, {}; return end
  local rows = {}
  for _, label in ipairs(M.entries) do
    local r = thmlookup.by_label[label]
    if r and r.display and r.display ~= '' then
      rows[#rows + 1] = '\\ProofReferenceEntry{' .. r.display .. '}{' ..
        (r.delta or '') .. '}{' .. r.env .. '}{' .. label .. '}{' ..
        (r.number or '?') .. '}'
    else
      texio.write_nl('proof-references WARNING: missing original statement: ' .. label)
      rows[#rows + 1] = '\\ProofReferenceMissing{' .. (r and r.env or '') ..
        '}{' .. label .. '}{' .. (r and r.number or '?') .. '}'
    end
  end
  M.entries, M.seen = {}, {}
  if #rows > 0 then
    -- sprint treats embedded newlines as literal character tokens.
    tex.sprint('\\ProofReferencesTable{' .. table.concat(rows, ' ') .. '}')
  end
end

return M
