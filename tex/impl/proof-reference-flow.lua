-- Break already typeset reference formulas without re-expanding their source.
-- The caller owns the input box.  Each prepared output box is owned here until
-- take() transfers it to a TeX box register exactly once.
local M = { stats = { lines = 0, wrapped = 0, unbreakable = 0 } }
local pending, next_id = {}, 0
local id = {}
for _, name in ipairs({"hlist", "vlist", "glyph", "glue", "kern", "penalty", "math", "rule", "whatsit"}) do
  id[name] = node.id(name)
end

-- graphicx and color/link commands put paired state changes into their boxes.
-- Moving a save, matrix, color push or link start to another output line than
-- its matching restore/pop/end would also transform the following table cell.
-- Keep their enclosing box intact; the caller can bound an indivisible box.
local stateful_whatsit, state_kind = {}, {}
for _, name in ipairs({ "pdf_save", "pdf_restore", "pdf_setmatrix",
    "pdf_literal", "pdf_colorstack", "pdf_start_link", "pdf_end_link" }) do
  local subtype = node.subtype(name)
  if subtype then
    stateful_whatsit[subtype] = true
    state_kind[subtype] = name
  end
end

local function state_is_closed(head)
  local saves, links, colors, valid = 0, 0, {}, true
  local function visit(list)
    for n in node.traverse(list) do
      if n.id == id.whatsit then
        local kind = state_kind[n.subtype]
        if kind == "pdf_save" then
          saves = saves + 1
        elseif kind == "pdf_restore" then
          saves = saves - 1
          if saves < 0 then valid = false end
        elseif kind == "pdf_setmatrix" then
          if saves == 0 then valid = false end
        elseif kind == "pdf_start_link" then
          links = links + 1
        elseif kind == "pdf_end_link" then
          links = links - 1
          if links < 0 then valid = false end
        elseif kind == "pdf_colorstack" then
          local stack = n.stack
          local depth = colors[stack] or 0
          if n.command == 1 then depth = depth + 1 end
          if n.command == 2 then depth = depth - 1 end
          if depth < 0 or (n.command == 0 and depth == 0) then valid = false end
          colors[stack] = depth
        elseif kind == "pdf_literal" then
          -- Arbitrary literal PDF can itself contain unbalanced operators.
          -- Do not infer that an enclosing save makes it safe to split.
          valid = false
        end
      elseif (n.id == id.hlist or n.id == id.vlist) and n.list then
        visit(n.list)
      end
    end
  end
  visit(head)
  if not valid or saves ~= 0 or links ~= 0 then return false end
  for _, depth in pairs(colors) do if depth ~= 0 then return false end end
  return true
end

local function requires_atomic(head)
  for n in node.traverse(head) do
    if n.id == id.whatsit and stateful_whatsit[n.subtype] then return true end
    if (n.id == id.hlist or n.id == id.vlist) and n.list and
        not state_is_closed(n.list) then return true end
  end
  return false
end

local function has_transform(head)
  for n in node.traverse(head) do
    if n.id == id.whatsit then
      local kind = state_kind[n.subtype]
      if kind == "pdf_save" or kind == "pdf_restore" or
          kind == "pdf_setmatrix" or kind == "pdf_literal" then return true end
    elseif (n.id == id.hlist or n.id == id.vlist) and n.list and
        has_transform(n.list) then return true end
  end
  return false
end

local function append(head, tail, item)
  item.next, item.prev = nil, tail
  if tail then tail.next = item else head = item end
  return head, item
end

local function has_ink(n)
  if n.id == id.glyph then return true end
  if n.id == id.rule then return (n.width or 0) > 0 end
  if n.id == id.whatsit then return true end
  if n.id == id.hlist or n.id == id.vlist then
    for child in node.traverse(n.list) do
      if has_ink(child) then return true end
    end
  end
  return false
end

-- Math boundaries and alignment struts carry no ink.  They must not prevent
-- recognition of an aligned/gathered object wrapped by the math machinery.
local function sole_visible(head)
  local found
  for n in node.traverse(head) do
    if has_ink(n) then
      if found then return nil end
      found = n
    end
  end
  return found
end

local function multiline_box(box)
  local current = box
  for _ = 1, 12 do
    if requires_atomic(current.list) then return nil end
    if current.id == id.vlist then
      local rows, kind, valid = {}, nil, true
      for n in node.traverse(current.list) do
        if n.id == id.hlist and has_ink(n) then
          -- Alignment rows and paragraph lines have explicit subtypes.
          -- In particular, numerator/denominator and operator-limit boxes do
          -- not: treating those as paragraph rows would change the formula.
          local rowkind = n.subtype == 4 and "math" or
            ((n.subtype == 1 or n.subtype == 6) and "text" or nil)
          if not rowkind or (kind and kind ~= rowkind) then valid = false end
          kind = kind or rowkind
          rows[#rows + 1] = n
        elseif has_ink(n) then
          valid = false
        end
      end
      if valid and #rows > 0 then return rows, kind end
    end
    local child = sole_visible(current.list)
    if not child or (child.id ~= id.hlist and child.id ~= id.vlist) then return nil end
    current = child
  end
end

-- Unpack horizontal math/alignment wrappers, preserving real scripts,
-- fractions and other vertical constructions as indivisible mathematical
-- objects.  Math glue retains the actual font's spacing and exposes legal
-- relation/binary-operator break positions even inside an aligned cell.
local function flatten(head)
  local result, tail
  local function visit(list)
    for n in node.traverse(list) do
      if n.id == id.hlist and (n.shift or 0) == 0 and n.list then
        if requires_atomic(n.list) then
          result, tail = append(result, tail, node.copy(n))
        elseif has_ink(n) then
          visit(n.list)
        end
      elseif n.id == id.math then
        -- mathsurround is zero in the renderer's isolated formula box.
      elseif n.id == id.glue and (n.width or 0) == 0 then
        -- Alignment hfil and tabskip have no natural visible separation.
      elseif n.id == id.kern and (n.kern or 0) < 0 and not tail then
        -- Empty alignment correction columns consist only of a negative kern.
      elseif (n.id == id.hlist or n.id == id.vlist or n.id == id.rule) and not has_ink(n) then
        -- Zero-width alignment struts only determine the original row height.
      else
        local copy = node.copy(n)
        result, tail = append(result, tail, copy)
        if n.id == id.glue and (n.subtype == 19 or n.subtype == 18 or n.subtype == 17) then
          local penalty = node.new("penalty")
          penalty.penalty = n.subtype == 19 and 20 or (n.subtype == 18 and 60 or 300)
          result, tail = append(result, tail, penalty)
        end
      end
    end
  end
  visit(head)
  return result
end

local function natural_box(head)
  -- The line breaker adds left/right/parfill skips.  Their natural width is
  -- zero; repacking removes justification while preserving all printed nodes.
  local box = node.hpack(head)
  return box
end

local function copy_text_line(row)
  local copy = node.copy(row)
  -- A paragraph line can report hsize although an unbreakable word protrudes.
  -- Measure its actual, already justified contents so the caller's final
  -- bounding fallback also covers that case without changing text spacing.
  local actual = node.dimensions(row.glue_set, row.glue_sign, row.glue_order, row.list)
  copy.width = math.max(copy.width, actual)
  if copy.shift ~= 0 then
    -- In its original vertical list shift means horizontal displacement;
    -- after insertion in a table hbox it would mean vertical displacement.
    local offset = node.new("kern")
    offset.kern = copy.shift
    copy.shift = 0
    offset.next, copy.prev = copy, offset
    return natural_box(offset)
  end
  return copy
end

local function break_math(box, width)
  if box.width <= width then return { node.copy(box) } end
  -- A transformation's outer wrapper also owns its corrected width, height,
  -- depth and displacement. Keeping only the save/matrix/restore child would
  -- balance PDF state but lose that geometry (especially for rotations).
  -- Preserve the complete mathematical row; a long aligned object has already
  -- been separated into its individual rows by multiline_box.
  if has_transform(box.list) then return { node.copy(box) } end
  -- This also covers state changes directly in the outer box, which flatten
  -- cannot protect by retaining a nested wrapper.
  if requires_atomic(box.list) then return { node.copy(box) } end
  local head = flatten(box.list)
  if not head then return {} end
  local measurement = natural_box(node.copy_list(head))
  local natural_width = measurement.width
  node.flush_node(measurement)
  if natural_width <= width then return { natural_box(head) } end
  local tail = node.tail(head)
  local no_break = node.new("penalty")
  no_break.penalty = 10000
  head, tail = append(head, tail, no_break)
  local fill = node.new("glue")
  fill.stretch, fill.stretch_order = 65536, 1
  head, tail = append(head, tail, fill)
  local stop = node.new("penalty")
  stop.penalty = -10000
  head, tail = append(head, tail, stop)
  local old_rightskip = { tex.getglue("rightskip") }
  tex.setglue("rightskip", 0, 65536, 0, 1, 0)
  local old_hfuzz, old_hbadness = tex.hfuzz, tex.hbadness
  tex.hfuzz, tex.hbadness = 1073741823, 10000
  local lines = tex.linebreak(head, { hsize = width, pretolerance = -1,
    tolerance = 10000, emergencystretch = width, looseness = 0,
    linepenalty = 10, hyphenpenalty = 10000, exhyphenpenalty = 10000 })
  tex.setglue("rightskip", table.unpack(old_rightskip))
  tex.hfuzz, tex.hbadness = old_hfuzz, old_hbadness
  local output = {}
  for line in node.traverse(lines) do
    if line.id == id.hlist and has_ink(line) then
      output[#output + 1] = natural_box(node.copy_list(line.list))
    end
  end
  node.flush_list(lines)
  if #output > 1 then M.stats.wrapped = M.stats.wrapped + 1 end
  return output
end

local function emit(boxes, width, maxheight, reference)
  for _, box in ipairs(boxes) do
    next_id = next_id + 1
    pending[next_id] = box
    M.stats.lines = M.stats.lines + 1
    if box.width > width + 655 or box.height + box.depth > maxheight then
      M.stats.unbreakable = M.stats.unbreakable + 1
      texio.write_nl("log", "proof-references: indivisible formula fragment requires bounded scaling")
    end
    tex.sprint("\\ProofReferenceFlowLine{" .. next_id .. "}{" .. (reference or "") .. "}")
  end
end

function M.prepare(boxnum, width, maxheight, reference)
  local box = assert(tex.box[boxnum], "proof reference input box is empty")
  if box.id == id.vlist then return M.prepare_text(boxnum, width, maxheight, reference) end
  if box.width <= width and box.height + box.depth <= maxheight then
    return emit({ node.copy(box) }, width, maxheight, reference)
  end
  local rows, kind = multiline_box(box)
  rows = rows or { box }
  local output = {}
  for _, row in ipairs(rows) do
    if kind == "text" then
      output[#output + 1] = copy_text_line(row)
    else
      for _, line in ipairs(break_math(row, width)) do output[#output + 1] = line end
    end
  end
  emit(output, width, maxheight, reference)
end

function M.prepare_text(boxnum, width, maxheight, reference)
  local box = assert(tex.box[boxnum], "proof reference text box is empty")
  local output = {}
  local function collect(current)
    if current.id == id.vlist then
      if requires_atomic(current.list) then
        output[#output + 1] = node.copy(current)
        return
      end
      for row in node.traverse(current.list) do
        if row.id == id.hlist and has_ink(row) then
          -- Already typeset text paragraphs retain their exact glyph spacing.
          output[#output + 1] = copy_text_line(row)
        elseif row.id == id.vlist then
          collect(row)
        elseif has_ink(row) then
          output[#output + 1] = natural_box(node.copy(row))
        end
      end
    else
      output[#output + 1] = node.copy(current)
    end
  end
  collect(box)
  emit(output, width, maxheight, reference)
end

function M.take(line_id, outboxnum)
  local box = assert(pending[line_id], "proof reference line was already consumed")
  pending[line_id] = nil
  tex.box[outboxnum] = box
end

return M
