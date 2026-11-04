# SUIDoku

Paste a list of SUID binaries and find the ones [GTFOBins](https://gtfobins.github.io/)
lists a **SUID privilege-escalation** vector for.

For authorized security testing, CTFs, and local hardening review.

## Requirements

- [`fish`](https://fishshell.com/) — the script interpreter
- [`jq`](https://jqlang.github.io/jq/) — parses the GTFOBins JSON
- `curl` **or** `wget` — fetches the API

## Usage

```sh
./SUIDoku                 # paste paths, one per line, then press Ctrl-D
find / -perm -4000 -type f 2>/dev/null | ./SUIDoku   # pipe the real SUID set
./SUIDoku -f suid_list.txt
```

Options:

| Flag        | Meaning                                                        |
|-------------|----------------------------------------------------------------|
| `-v`        | Verbose — also print the exploit technique(s) for each match   |
| `-q`        | Quiet — print matching paths only (scriptable)                 |
| `-r`        | Refresh the cached GTFOBins API data                           |
| `-c CTX`    | Filter on a different context (`sudo`, `unprivileged`, …)       |
| `-f FILE`   | Read paths from `FILE` instead of stdin                        |
| `-h`        | Help                                                            |

Input is one binary path per line (full paths or bare names); blank lines and
`#` comments are ignored. Matching is by basename.

## Install
This will install the script as a symlink so that `git pull` keeps it updated:

```fish
ln -sf (realpath SUIDoku.fish) ~/.local/bin/SUIDoku
```

## How it works

Data comes from `https://gtfobins.org/api.json` (override with
`SUIDOKU_API_URL`). A binary counts as a match when any of its GTFOBins
techniques lists the `suid` context. The API response is cached under
`${XDG_CACHE_HOME:-~/.cache}/suidoku/` and reused indefinitely — GTFOBins
changes rarely, so SUIDoku only re-downloads when the cache is missing or you
pass `-r`.
