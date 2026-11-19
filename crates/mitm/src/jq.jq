def IN(s): any(s == .; .);
def IN(src; s): any(src == s; .);

def INDEX(stream; f): reduce stream as $row ({}; .[$row | f | tostring] = $row);
def INDEX(f): INDEX(.[]; f);
def JOIN($index; f): [.[] | [., $index[f]]];
def JOIN($index; stream; f): stream | [., $index[f]];
def JOIN($index; stream; f; g): stream | [., $index[f]] | g;

def tostream:
  def events($path):
    if (type == "array" or type == "object") and length > 0
    then (path(.[])[0] as $key | .[$key] | events($path + [$key])),
      [$path + [last(path(.[])[0])]]
    else [$path, .] end;
  events([]);
def fromstream(events):
  def place($path; $leaf):
    if $path == [] then $leaf
    else $path[0] as $key
      | if ($key | type) == "number"
        then (. // []) | .[:$key] + [.[$key] | place($path[1:]; $leaf)] + .[$key + 1:]
        else (. // {}) + {($key): (.[$key] | place($path[1:]; $leaf))} end end;
  foreach events as $event ({value: null, done: false};
    if .done then {value: null, done: false} end
    | if $event | length == 2
      then .value |= place($event[0]; $event[1]) | .done = ($event[0] | length == 0)
      else .done = ($event[0] | length == 1) end;
    if .done then .value else empty end);
def truncate_stream(stream):
  . as $depth | null | stream | select(.[0] | length > $depth) | .[0] |= .[$depth:];

def tabular_row($separator; quote; $format):
  if type != "array" then error("\(type) (\(tojson)) cannot be \($format)-formatted, only an array can be") end
  | [.[] | if type == "string" then quote
    elif type == "number" or type == "boolean" then tostring
    elif . == null then ""
    else error("\(type) (\(tojson)) is not valid in a \($format) row") end]
  | join($separator);
def @csv: tabular_row(","; "\"" + (split("\"") | join("\"\"")) + "\""; "csv");
def @tsv:
  tabular_row("\t";
    split("\\") | join("\\\\") | split("\t") | join("\\t")
    | split("\n") | join("\\n") | split("\r") | join("\\r");
    "tsv");
