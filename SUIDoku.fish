#!/usr/bin/env fish
#
# SUIDoku — paste a list of SUID binaries, find the ones GTFOBins lists a
#           privilege-escalation vector for.
#
# For authorized security testing, CTFs, and local hardening review.
#
# Usage:
#   SUIDoku                 # paste paths, then press Ctrl-D
#   find / -perm -4000 -type f 2>/dev/null | SUIDoku
#   SUIDoku -f suid_list.txt
#   SUIDoku -v              # also print the exploit technique(s)
#   SUIDoku -q              # print matching paths only (scriptable)
#   SUIDoku -r              # force-refresh the cached API data

set -g API_URL (test -n "$SUIDOKU_API_URL"; and echo $SUIDOKU_API_URL; or echo 'https://gtfobins.org/api.json')
set -g CACHE_DIR (test -n "$XDG_CACHE_HOME"; and echo $XDG_CACHE_HOME; or echo "$HOME/.cache")/suidoku
set -g CACHE_FILE "$CACHE_DIR/api.json"
set -g CONTEXT suid

set -g verbose 0
set -g quiet 0
set -g refresh 0
set -g infile ''

# --- colors (only when stdout is a tty) --------------------------------------
set -g c_grn ''; set -g c_cyn ''; set -g c_dim ''; set -g c_rst ''
if isatty stdout
    set c_grn (set_color green)
    set c_cyn (set_color cyan)
    set c_dim (set_color brblack)
    set c_rst (set_color normal)
end

function err
    echo "SUIDoku: $argv" >&2
end

function usage
    echo "SUIDoku — match local SUID binaries against GTFOBins privesc vectors

Usage: SUIDoku [-v|-q] [-r] [-c CONTEXT] [-f FILE]

  -f FILE   Read binary paths from FILE instead of stdin
  -v        Verbose: show the exploit technique(s) for each match
  -q        Quiet: print matching paths only (no decoration)
  -r        Refresh the cached GTFOBins API data before running
  -c CTX    GTFOBins context to filter on (default: suid; e.g. sudo, unprivileged)
  -h        Show this help

Input: one binary path per line (full paths or bare names); blank lines
and lines starting with '#' are ignored. Matching is by basename." >&2
end

# --- argument parsing --------------------------------------------------------
if not argparse 'v/verbose' 'q/quiet' 'r/refresh' 'h/help' 'f/file=' 'c/context=' -- $argv 2>/dev/null
    usage
    exit 2
end
set -q _flag_help; and begin; usage; exit 0; end
set -q _flag_verbose; and set verbose 1
set -q _flag_quiet; and set quiet 1
set -q _flag_refresh; and set refresh 1
set -q _flag_file; and set infile $_flag_file
set -q _flag_context; and set CONTEXT $_flag_context

# --- dependency checks -------------------------------------------------------
if not command -q jq
    err "jq is required"; exit 1
end

set -g downloader
if command -q curl
    set downloader curl -fsSL --max-time 30
else if command -q wget
    set downloader wget -qO-
else
    err "need either curl or wget to fetch the API"; exit 1
end

# --- fetch / cache the API ---------------------------------------------------
function fetch_api
    mkdir -p "$CACHE_DIR"
    # The cache never expires: once fetched it is reused forever. Only -r
    # (refresh) or a missing/empty cache triggers a download. GTFOBins data
    # changes rarely, so re-fetch on your own schedule with `SUIDoku -r`.
    if test "$refresh" -eq 0; and test -s "$CACHE_FILE"
        return 0
    end
    test "$quiet" -eq 1; or err "fetching $API_URL ..."
    set -l tmp "$CACHE_DIR/.api.json.$fish_pid"
    if not $downloader "$API_URL" >"$tmp" 2>/dev/null
        rm -f "$tmp"
        if test -s "$CACHE_FILE"
            err "download failed; using cached data"; return 0
        end
        err "download failed and no cache available"; return 1
    end
    if not jq -e . "$tmp" >/dev/null 2>&1
        rm -f "$tmp"
        if test -s "$CACHE_FILE"
            err "downloaded data was not valid JSON; using cached data"; return 0
        end
        err "downloaded data was not valid JSON"; return 1
    end
    mv -f "$tmp" "$CACHE_FILE"
end

# --- gather input ------------------------------------------------------------
set -g tmp_in (mktemp (test -n "$TMPDIR"; and echo $TMPDIR; or echo /tmp)/suidoku.in.XXXXXX)
function _cleanup --on-event fish_exit
    rm -f "$tmp_in"
end

if test -n "$infile"
    if not test -r "$infile"
        err "cannot read file: $infile"; exit 1
    end
    cat -- "$infile" >"$tmp_in"
else if not isatty stdin
    cat >"$tmp_in"
else
    err "Paste SUID binary paths, one per line, then press Ctrl-D:"
    cat >"$tmp_in"
end

fetch_api; or exit 1

# --- parse & report ----------------------------------------------------------
# Normalize input to unique basenames (dropping blanks/comments), then let jq
# do all the matching. jq receives:
#   $context : the GTFOBins context to filter on
#   --slurpfile wanted : [ {path, name} ... ] from the pasted list
#   the API json on stdin
# and emits TSV rows:  path <TAB> name <TAB> "Label1, Label2" <TAB> verbose-block

set -l wanted_file (mktemp (test -n "$TMPDIR"; and echo $TMPDIR; or echo /tmp)/suidoku.want.XXXXXX)
# build [{path,name}] preserving first occurrence order, de-duplicated by path
grep -vE '^[[:space:]]*($|#)' "$tmp_in" \
    | awk '!seen[$0]++ {print}' \
    | jq -R '{path: ., name: (. | sub("^.*/"; ""))}' \
    | jq -s '.' >"$wanted_file"

set -l total (jq 'length' "$wanted_file")

set -l jq_filter '
  ($wanted[0]) as $want
  | (.functions // {}) as $labels
  | [ $want[]
      | . as $w
      | ($exec[$w.name] // empty) as $e
      | [ $e.functions // {} | to_entries[]
          | .key as $fn
          | .value[]
          | select((.contexts // {}) | has($context))
          | { fn: $fn,
              label: ($labels[$fn].label // $fn),
              code: ( (.contexts[$context] | if type=="object" and has("code") then .code else null end) // .code // "" ),
              comment: (.comment // "") } ] as $vectors
      | select(($vectors | length) > 0)
      | { path: $w.path, name: $w.name, vectors: $vectors }
    ]
'

# emit JSON array of matches
jq --arg context "$CONTEXT" --slurpfile wanted "$wanted_file" \
   '. as $root | ($root.executables // {}) as $exec | '"$jq_filter" \
   "$CACHE_FILE" >"$wanted_file.out"
rm -f "$wanted_file"

set -l nmatch (jq 'length' "$wanted_file.out")

if test "$quiet" -eq 1
    jq -r '.[].path' "$wanted_file.out"
    rm -f "$wanted_file.out"
    exit 0
end

if test "$nmatch" -eq 0
    echo
    echo "No '$CONTEXT' privilege-escalation vectors found ($total binaries checked)."
    rm -f "$wanted_file.out"
    exit 0
end

echo
echo "$nmatch of $total binaries have a known '$CONTEXT' privilege-escalation vector:"
echo

# iterate matches as compact JSON lines
for row in (jq -c '.[]' "$wanted_file.out")
    set -l path (echo $row | jq -r '.path')
    set -l name (echo $row | jq -r '.name')
    set -l funcs (echo $row | jq -r '[.vectors[].label] | unique | join(", ")')
    set -l url "https://gtfobins.github.io/gtfobins/$name/"
    echo "  "$c_grn"[+]"$c_rst" $path"
    echo "      $c_dim""vectors:$c_rst $funcs"
    echo "      $c_dim""ref:$c_rst     $c_cyn$url$c_rst"
    if test "$verbose" -eq 1
        for vec in (echo $row | jq -c '.vectors[]')
            set -l label (echo $vec | jq -r '.label')
            echo "      $c_dim· $label:$c_rst"
            echo $vec | jq -r '.code' | while read -l cl
                echo "          $cl"
            end
            set -l comment (echo $vec | jq -r '.comment')
            test -n "$comment"; and echo "          $c_dim# $comment$c_rst"
        end
    end
    echo
end

rm -f "$wanted_file.out"
