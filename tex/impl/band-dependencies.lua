-- Gemeinsame TeX/Lua-Seite des in band-dependencies.tsv definierten
-- Bandgraphen.  Perl (latexmkrc) und PowerShell lesen dieselbe Datei.

local M = banddeps or {}

M.graph_path = "band-dependencies.tsv"
M.graph = nil

local function split_tsv(line)
  local fields = {}
  local start = 1
  while true do
    local tab = line:find("\t", start, true)
    if not tab then
      fields[#fields + 1] = line:sub(start)
      return fields
    end
    fields[#fields + 1] = line:sub(start, tab - 1)
    start = tab + 1
  end
end

local function fail(message)
  error("band-dependencies.tsv: " .. message, 0)
end

local function read_graph()
  if M.graph then
    return M.graph
  end

  local file = io.open(M.graph_path, "r")
  if not file then
    fail("cannot open " .. M.graph_path)
  end

  local graph = {}
  local order = {}
  local line_number = 0
  for raw_line in file:lines() do
    line_number = line_number + 1
    local line = raw_line:gsub("\r$", "")
    if line ~= "" and not line:match("^%s*#") then
      local fields = split_tsv(line)
      if line_number == 1 and fields[1] == "band" then
        if fields[2] ~= "source" or fields[3] ~= "artifact_base"
           or fields[4] ~= "predecessors" then
          fail("invalid header")
        end
      else
        if #fields ~= 4 then
          fail("line " .. line_number .. " must contain four TSV columns")
        end
        local tag, source, artifact_base, predecessor_text =
          fields[1], fields[2], fields[3], fields[4]
        if not tag:match("^B%d%d$") then
          fail("invalid band tag on line " .. line_number .. ": " .. tag)
        end
        if graph[tag] then
          fail("duplicate band " .. tag)
        end
        if source ~= tag .. ".tex" then
          fail("source mapping for " .. tag .. " must be " .. tag .. ".tex")
        end
        if artifact_base ~= "registry/_" .. tag then
          fail("artifact mapping for " .. tag .. " must be registry/_" .. tag)
        end

        local predecessors = {}
        if predecessor_text ~= "" then
          for predecessor in predecessor_text:gmatch("[^,]+") do
            if not predecessor:match("^B%d%d$") then
              fail("invalid predecessor for " .. tag .. ": " .. predecessor)
            end
            predecessors[#predecessors + 1] = predecessor
          end
        end
        graph[tag] = {
          tag = tag,
          source = source,
          artifact_base = artifact_base,
          predecessors = predecessors,
        }
        order[#order + 1] = tag
      end
    end
  end
  file:close()

  for _, tag in ipairs(order) do
    local seen = {}
    for _, predecessor in ipairs(graph[tag].predecessors) do
      if not graph[predecessor] then
        fail("unknown predecessor " .. predecessor .. " for " .. tag)
      end
      if seen[predecessor] then
        fail("duplicate predecessor " .. predecessor .. " for " .. tag)
      end
      seen[predecessor] = true
    end
  end

  local visiting, visited = {}, {}
  local function visit(tag)
    if visiting[tag] then
      fail("dependency cycle at " .. tag)
    end
    if visited[tag] then
      return
    end
    visiting[tag] = true
    for _, predecessor in ipairs(graph[tag].predecessors) do
      visit(predecessor)
    end
    visiting[tag] = nil
    visited[tag] = true
  end
  for _, tag in ipairs(order) do
    visit(tag)
  end

  M.graph = graph
  return graph
end

local function specification(tag)
  local spec = read_graph()[tag]
  if not spec then
    fail("unknown target " .. tostring(tag))
  end
  return spec
end

function M.emit_external_documents(tag)
  local spec = specification(tag)
  local dependency_pdf_is_sibling = tex.jobname == "_" .. tag
  for _, predecessor in ipairs(spec.predecessors) do
    local predecessor_spec = specification(predecessor)
    local pdf_url
    if dependency_pdf_is_sibling then
      pdf_url = predecessor_spec.artifact_base:match("([^/]+)$") .. ".pdf"
    else
      pdf_url = predecessor_spec.artifact_base .. ".pdf"
    end
    tex.sprint(
      "\\externaldocument{" .. predecessor_spec.artifact_base .. "}[" .. pdf_url .. "]"
    )
  end
end

function M.load_predecessor_registries(tag)
  local spec = specification(tag)
  for _, predecessor in ipairs(spec.predecessors) do
    local registry = specification(predecessor).artifact_base .. ".registry.tsv"
    local file = io.open(registry, "r")
    if file then
      file:close()
    else
      texio.write_nl("band-dependencies ERROR: missing registry import: " .. registry)
    end
    thmlookup.load_registry_file(registry)
  end
end

function M.setup_standalone(tag)
  local spec = specification(tag)
  local registry_path = spec.artifact_base .. ".registry.tsv"
  local debug_path = spec.artifact_base .. ".debug.log"
  if thmlookup.prepared_registry_path ~= registry_path then
    thmlookup.registry_path = registry_path
    thmlookup.debug_path = debug_path
    thmlookup.prepare_run()
  else
    -- The normal Bxx/_Bxx job names are configured before thmlookup.tex calls
    -- prepare_run().  Keep the matching debug path explicit without preparing
    -- twice, because a second prepare would discard the loaded self-registry
    -- needed for forward references on the first pass.
    thmlookup.registry_path = registry_path
    thmlookup.debug_path = debug_path
  end
  local job = tex.jobname or ""
  if job ~= tag and job ~= "_" .. tag then
    texio.write_nl(
      "band-dependencies WARNING: target " .. tag .. " is built with unexpected jobname " .. job
    )
  end
  M.load_predecessor_registries(tag)
end

function M.start_band_in_main(tag)
  local spec = specification(tag)
  thmlookup.registry_path = spec.artifact_base .. ".registry.tsv"
  thmlookup.debug_path = spec.artifact_base .. ".debug.log"
  thmlookup.prepare_run()
  M.load_predecessor_registries(tag)
  texio.write_nl("thmlookup: main output -> " .. thmlookup.registry_path)
end

read_graph()
banddeps = M
return M
