-- Edition-local audit of uses and of the actual reference-table renderer.
-- The shared proof-reference implementation remains responsible for all output.
local output = assert(io.open("registry/coordinates/" .. tex.jobname .. ".proof-references.tsv", "w"))
local current = 0
local function write(...)
  local fields = {...}
  for i, value in ipairs(fields) do fields[i] = tostring(value) end
  output:write(table.concat(fields, "\t"), "\n")
  output:flush()
end
local original_begin = proofreferences.begin_proof
function proofreferences.begin_proof(...)
  if proofreferences.depth == 0 then
    current = current + 1
    write("begin", current)
  end
  return original_begin(...)
end
local original_record = proofreferences.record
function proofreferences.record(label)
  if proofreferences.depth > 0 and thmlookup.by_label[label] then
    write("use", current, label)
  end
  return original_record(label)
end
local original_end = proofreferences.end_proof
function proofreferences.end_proof(enabled)
  if proofreferences.depth == 1 then write("closed", current) end
  return original_end(enabled)
end
local original_emit = proofreferences.emit_entry
function proofreferences.emit_entry(display, delta, env, label, number)
  write("entry", current, label, env, number, #(display or ""), #(delta or ""))
  return original_emit(display, delta, env, label, number)
end
return {
  finish = function()
    assert(proofreferences.depth == 0, "Coordinate proof-reference scope remains open")
    output:close()
  end,
}
