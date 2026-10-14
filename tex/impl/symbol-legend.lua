-- Page-local symbol collection for LuaLaTeX.
--
-- TeX owns symbol rendering, links, page geometry and the vertical overflow
-- check; assert_box_fits checks horizontal contents after the legend is packed.
-- Call collect exactly once after every shipout discard decision and before
-- adding the legend. Suppress mark calls while typesetting legends. Merely
-- calling in shipout/before is insufficient: later code may discard that page.
-- The TeX adapter uses shipout/foreground for standard vertical LaTeX pages;
-- horizontal/raw shipouts are unsupported and must fail rather than disappear.
-- A marker must stay with the symbol's math atom / unbreakable text unit.
-- Merely inserting a marker in vertical mode can move it to another page.
--
-- Only shipped nodes introduce a symbol. External introductions have page 0.
-- Introduction markers are not themselves uses: mark(id, true) should be
-- accompanied by mark(id, false) if the introduction prints the symbol.

local M = {}
local registry, by_id, pages = {}, {}, {}
local absolute_page = 0

local function fail(message)
  error("symbol-legend: " .. message, 2)
end

if not (node and tex and luatexbase and luatexbase.new_whatsit) then
  fail("LuaLaTeX with luatexbase.new_whatsit is required")
end

local hlist_id = node.id("hlist")
local vlist_id = node.id("vlist")
local disc_id = node.id("disc")
local glue_id = node.id("glue")
local whatsit_id = node.id("whatsit")
local glyph_id = node.id("glyph")
local rule_id = node.id("rule")
local user_defined = node.subtype("user_defined")
local use_marker = luatexbase.new_whatsit("symbol-legend/use")
local introduction_marker = luatexbase.new_whatsit("symbol-legend/introduction")

local function check_id(id)
  -- IDs are emitted as a TeX macro argument, so TeX syntax is forbidden.
  if type(id) ~= "string" or not id:match("^[A-Za-z][A-Za-z0-9:_.%-]*$") then
    fail("invalid symbol ID (use ASCII letters, digits, colon, dot, underscore or hyphen)")
  end
end

local function boolean(value, argument)
  if value == nil then return false end
  if type(value) ~= "boolean" then
    fail(argument .. " must be a Lua boolean")
  end
  return value
end

local function symbol(id)
  check_id(id)
  if not by_id[id] then fail("unknown symbol ID '" .. id .. "'") end
  return by_id[id]
end

function M.declare(id, external_introduction, reading_introduction)
  check_id(id)
  if by_id[id] then fail("duplicate symbol ID '" .. id .. "'") end
  external_introduction = boolean(external_introduction, "external_introduction")
  reading_introduction = boolean(reading_introduction, "reading_introduction")
  if external_introduction and reading_introduction then
    fail("a reading introduction must be local to the current PDF")
  end
  local entry = {
    id = id,
    index = #registry + 1,
    external_introduction = external_introduction,
    reading_introduction = reading_introduction,
    introduced_page = external_introduction and 0 or nil,
  }
  registry[#registry + 1] = entry
  by_id[id] = entry
  M.write_audit()
  return entry.index
end

function M.mark(id, is_introduction)
  local entry = symbol(id)
  is_introduction = boolean(is_introduction, "is_introduction")
  local marker = node.new(whatsit_id, user_defined)
  marker.user_id = is_introduction and introduction_marker or use_marker
  marker.type = 100 -- numeric payload, copied together with the node
  marker.value = entry.index
  node.write(marker)
end

local function ordered_ids(set)
  local result = {}
  for _, entry in ipairs(registry) do
    if set[entry.index] then result[#result + 1] = entry.id end
  end
  return result
end

local function marker_entry(n)
  if n.type ~= 100 or type(n.value) ~= "number"
      or n.value % 1 ~= 0 or not registry[n.value] then
    fail("invalid symbol marker in the shipped page")
  end
  return registry[n.value]
end

-- Do not inspect unused discretionary branches. Once line breaking has run,
-- chosen pre/post material is in the final line lists; a remaining disc emits
-- its no-break replacement. This also covers discretionaries in an hbox.
-- Preserve the existing nodes and all unselected branches. Only the first
-- shipped introduction of a reading-local symbol receives a PDF destination.
-- Inserting it here avoids destinations in discarded measurements, unused
-- mathchoice branches and later copies of an already introduced symbol.
local function scan(head, used, introductions, counts, in_leader, reading_firsts)
  for n in node.traverse(head) do
    if n.id == hlist_id or n.id == vlist_id then
      if n.head then
        n.head = scan(n.head, used, introductions, counts, in_leader, reading_firsts)
      end
    elseif n.id == disc_id then
      if n.replace then
        n.replace = scan(n.replace, used, introductions, counts, in_leader, reading_firsts)
      end
    elseif n.id == glue_id and n.leader then
      -- A leader box may repeat zero times. Counting its stored nodes would
      -- manufacture uses. Reject marked leaders instead of silently guessing.
      scan(n.leader, used, introductions, counts, true, reading_firsts)
    elseif n.id == whatsit_id and n.subtype == user_defined
        and (n.user_id == use_marker or n.user_id == introduction_marker) then
      local entry = marker_entry(n)
      if in_leader then
        fail("symbol '" .. entry.id .. "' occurs in a leader; marked leaders are unsupported")
      end
      if n.user_id == introduction_marker then
        introductions[entry.index] = true
        if entry.reading_introduction and not entry.reading_anchor then
          local anchor = "slreading:" .. entry.id
          local destination = node.new("whatsit", "pdf_dest")
          destination.named_id = 1
          destination.dest_id = anchor
          destination.dest_type = 0 -- XYZ, matching \pdfextension dest ... xyz
          destination.xyz_zoom = 0
          head = node.insert_before(head, n, destination)
          entry.reading_anchor = anchor
          reading_firsts[entry.index] = true
        end
      else
        used[entry.index] = true
        counts[entry.id] = (counts[entry.id] or 0) + 1
      end
    end
  end
  return head
end

local function json_string(value)
  local escapes = {
    ['"'] = '\\"', ['\\'] = '\\\\',
    ['\b'] = '\\b', ['\f'] = '\\f', ['\n'] = '\\n',
    ['\r'] = '\\r', ['\t'] = '\\t',
  }
  return '"' .. tostring(value):gsub('[%z\1-\31\\"]', function(c)
    return escapes[c] or string.format("\\u%04x", string.byte(c))
  end) .. '"'
end

local function json_array(values)
  local result = {}
  for i, value in ipairs(values) do result[i] = json_string(value) end
  return "[" .. table.concat(result, ",") .. "]"
end

local function audit_paths()
  local directory = (status and status.output_directory) or "."
  if directory == "" then directory = "." end
  directory = directory:gsub("\\", "/"):gsub("/$", "")
  local jobname = tostring(tex.jobname or "texput")
  if jobname:find("[/\\%z]") then fail("jobname must not contain a path") end
  local base = directory .. "/" .. jobname .. ".symbol-legend"
  return base .. ".json", base .. ".tsv", jobname
end

local function write_file(path, contents)
  local file, message = io.open(path, "wb")
  if not file then fail("cannot open audit file '" .. path .. "': " .. tostring(message)) end
  local ok, write_message = file:write(contents)
  local closed, close_message = file:close()
  if not ok then fail("cannot write audit file '" .. path .. "': " .. tostring(write_message)) end
  if not closed then fail("cannot close audit file '" .. path .. "': " .. tostring(close_message)) end
end

function M.write_audit()
  local json_path, tsv_path, jobname = audit_paths()
  local declarations = {}
  for _, entry in ipairs(registry) do
    declarations[#declarations + 1] = "{" ..
      '"id":' .. json_string(entry.id) ..
      ',"index":' .. entry.index ..
      ',"external_introduction":' .. tostring(entry.external_introduction) ..
      ',"reading_introduction":' .. tostring(entry.reading_introduction) ..
      ',"introduced_page":' .. tostring(entry.introduced_page or "null") ..
      ',"introduced_tex_page":' .. tostring(entry.introduced_tex_page or "null") ..
      ',"reading_anchor":' .. (entry.reading_anchor and json_string(entry.reading_anchor) or "null") .. "}"
  end
  local page_json = {}
  local tsv = {
    "absolute_page\ttex_page\tused\tintroductions_on_page\tintroduced\tvisible\tunintroduced\n"
  }
  for _, page in ipairs(pages) do
    local counts = {}
    for _, id in ipairs(page.used) do
      counts[#counts + 1] = json_string(id) .. ":" .. page.use_counts[id]
    end
    page_json[#page_json + 1] = "{" ..
      '"absolute_page":' .. page.absolute_page ..
      ',"tex_page":' .. page.tex_page ..
      ',"used":' .. json_array(page.used) ..
      ',"introductions_on_page":' .. json_array(page.introductions_on_page) ..
      ',"introduced":' .. json_array(page.introduced) ..
      ',"visible":' .. json_array(page.visible) ..
      ',"unintroduced":' .. json_array(page.unintroduced) ..
      ',"use_counts":{' .. table.concat(counts, ",") .. "}}"
    tsv[#tsv + 1] = table.concat({
      page.absolute_page, page.tex_page,
      table.concat(page.used, ","), table.concat(page.introductions_on_page, ","),
      table.concat(page.introduced, ","), table.concat(page.visible, ","),
      table.concat(page.unintroduced, ","),
    }, "\t") .. "\n"
  end
  write_file(json_path, '{"schema_version":1,"jobname":' .. json_string(jobname) ..
    ',"absolute_page_count":' .. absolute_page ..
    ',"declarations":[' .. table.concat(declarations, ",") ..
    '],"pages":[' .. table.concat(page_json, ",") .. "]}\n")
  write_file(tsv_path, table.concat(tsv))
end

function M.collect(box_number)
  if type(box_number) ~= "number" or box_number % 1 ~= 0 or box_number < 0 then
    fail("collect expects a nonnegative box-register number")
  end
  local box = tex.box[box_number]
  if not box then fail("collect received an empty shipout box") end
  if box.id ~= vlist_id then
    fail("collect requires a standard vertical LaTeX shipout box")
  end
  local used, introductions, counts, reading_firsts = {}, {}, {}, {}
  scan(box, used, introductions, counts, false, reading_firsts)

  absolute_page = absolute_page + 1
  -- First process every introduction on the page; use order is irrelevant.
  for index in pairs(introductions) do
    local entry = registry[index]
    if entry.introduced_page == nil then
      entry.introduced_page = absolute_page
      entry.introduced_tex_page = tonumber(tex.count["c@page"]) or 0
    end
  end
  local introduced, visible, unintroduced = {}, {}, {}
  for _, entry in ipairs(registry) do
    if entry.introduced_page ~= nil and entry.introduced_page <= absolute_page then
      introduced[entry.index] = true
      if used[entry.index] then visible[entry.index] = true end
    elseif used[entry.index] then
      unintroduced[entry.index] = true
    end
  end
  local page = {
    absolute_page = absolute_page,
    tex_page = tonumber(tex.count["c@page"]) or 0,
    used = ordered_ids(used),
    introductions_on_page = ordered_ids(introductions),
    introduced = ordered_ids(introduced),
    visible = ordered_ids(visible),
    unintroduced = ordered_ids(unintroduced),
    use_counts = counts,
  }
  pages[#pages + 1] = page
  -- The TeX adapter expands \thepage and installs/writes its local newlabel.
  -- This preserves roman/alphabetic/custom page numbering, whereas c@page is
  -- only the numeric counter recorded by the audit. These callbacks precede
  -- SLPageEntries, so links work even on the introduction page in this run.
  for _, id in ipairs(ordered_ids(reading_firsts)) do
    tex.sprint("\\SLReadingIntroduction{" .. id .. "}{\\thepage}{" ..
      by_id[id].reading_anchor .. "}{" .. absolute_page .. "}")
  end
  local entries = {}
  for _, id in ipairs(page.visible) do
    entries[#entries + 1] = "\\SymbolLegendEntry{" .. id .. "}"
  end
  tex.sprint("\\gdef\\SLPageEntries{" .. table.concat(entries) .. "}")
  -- Write after each page, so a hard TeX
  -- overflow error still leaves an audit for the page that could not fit.
  M.write_audit()
  return page
end

-- Inspect the packed contents, not each nested box against its own width:
-- a zero-width overlay may legitimately extend into space in its enclosing
-- line. Propagating its extent to the outer legend avoids that false alarm.
-- The widths returned by node.dimensions include the enclosing hlist's actual
-- glue adjustment; its final argument is the first node NOT in the range.
local box_bounds
local function horizontal_bounds(head, owner)
  local x, left, right = 0, 0, 0
  local function include(a, b)
    left, right = math.min(left, a), math.max(right, b)
  end
  for n in node.traverse(head) do
    local advance = node.dimensions(
      owner.glue_set, owner.glue_sign, owner.glue_order, n, n.next)
    if n.id == hlist_id or n.id == vlist_id then
      local a, b = box_bounds(n)
      include(x + a, x + b)
    elseif n.id == disc_id and n.replace then
      local a, b = horizontal_bounds(n.replace, owner)
      include(x + a, x + b)
    elseif n.id == glyph_id or n.id == rule_id then
      include(x, x + advance)
    end
    x = x + advance
  end
  include(x, x)
  return left, right
end

box_bounds = function(box)
  if box.dir and box.dir ~= "TLT" then
    fail("horizontal legend validation requires left-to-right boxes")
  end
  local left, right = 0, math.max(0, box.width)
  if box.id == hlist_id then
    local a, b = horizontal_bounds(box.head, box)
    return math.min(left, a), math.max(right, b)
  end
  for n in node.traverse(box.head) do
    if n.id == hlist_id or n.id == vlist_id then
      local a, b = box_bounds(n)
      local shift = n.shift or 0
      left, right = math.min(left, shift + a), math.max(right, shift + b)
    elseif n.id == rule_id then
      -- A running rule takes the surrounding vlist's width.
      local width = n.width < -1073741823 and box.width or n.width
      right = math.max(right, width)
    end
  end
  return left, right
end

function M.assert_box_fits(box_number, expected_width, entry_id)
  if type(box_number) ~= "number" or box_number % 1 ~= 0 or box_number < 0 then
    fail("assert_box_fits expects a nonnegative box-register number")
  end
  local box = tex.box[box_number]
  if not box then fail("assert_box_fits received an empty legend box") end
  local limit = expected_width or box.width
  if type(limit) ~= "number" or limit <= 0 then
    fail("assert_box_fits expects a positive width in scaled points")
  end
  local left, right = box_bounds(box)
  local tolerance = 32768 -- half a TeX point; tolerates rounding/protrusion
  if left < -tolerance or right > limit + tolerance then
    fail(string.format(
      "legend horizontal overflow%s on physical page %d: contents [%.2fpt, %.2fpt] exceed [0pt, %.2fpt]",
      entry_id and (" in entry " .. entry_id) or "",
      absolute_page, left / 65536, right / 65536, limit / 65536))
  end
  return true
end

-- Create fresh audits even on a run without shipped pages, preventing stale
-- results. Declarations and collections update them synchronously. Do not
-- install a stop_run callback: that replaces LuaTeX's normal final statistics.
M.write_audit()

return M
