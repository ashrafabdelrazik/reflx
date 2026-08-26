# reflx

A single-binary URL-collection + parameter-fuzzing tool for **authorized**
bug bounty / pentest work. Point it at a host or a single URL and it
collects/dedupes endpoints, builds a per-endpoint parameter wordlist from
the live response, and fires a combined **XSS + SQLi + SSTI** probe at every
parameter as both GET and POST — all while showing a live terminal
dashboard with progress bars, a rolling request log, and a findings counter.

```
██████╗ ███████╗███████╗██╗     ██╗  ██╗
██╔══██╗██╔════╝██╔════╝██║     ╚██╗██╔╝
██████╔╝█████╗  █████╗  ██║      ╚███╔╝
██╔══██╗██╔══╝  ██╔══╝  ██║      ██╔██╗
██║  ██║███████╗██║     ███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝

target: example.com  mode: host  elapsed: 42s

overall [██████████████████------------]  60% (312/520) endpoints tested
current [████████████████████████------]  80% (16/20) https://example.com/render?tpl=x&id=9

[GET]   https://example.com/render?tpl=x&id=9&debug=%22%27%3E%3Cscript%3E...
[POST]  https://example.com/render?tpl=x&id=9  [body: debug=%27%22%60%29]
...(10 lines, rolling)

XSS 3   SQLi 1   SSTI 0   total 4
```

## Table of contents

- [Features](#features)
- [Installation](#installation)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Live dashboard](#live-dashboard)
- [Full usage / flags](#full-usage--flags)
- [Output format](#output-format)
- [Scope reminder](#scope-reminder)
- [License](#license)

## Features

- **Two modes** — point it at a bare **host** for full collection + testing,
  or a single **URL** to test just that one endpoint.
- **Multi-source URL collection** — Wayback CDX API (built in), plus `gau`,
  `katana`, and `waymore` if they're installed. Missing tools are silently
  skipped. (VirusTotal is deliberately excluded from waymore's sources — see
  [Installation](#installation).)
- **Smart deduplication** — numeric/UUID/hex path segments and tracking
  query params (`utm_*`, `fbclid`, `gclid`, etc.) are normalized away so
  `/profile/123`, `/profile/321`, and `/profile/555?utm_medium=x` all
  collapse into a single test target instead of three redundant ones.
- **Dynamic per-endpoint wordlists** — built from the URL's own params,
  live `<input>/<select>/<textarea>` field names, JSON keys in the
  response, and a built-in high-value default list — capped with
  `-max-params` so JSON-heavy pages don't balloon into thousands of
  requests.
- **Required parameters are preserved** — if an endpoint needs `?id=1` to
  work at all, that param rides along on every single test request (GET or
  POST) for every *other* parameter being fuzzed, and is itself tested as a
  POST field too.
- **One combined payload per parameter** — XSS + SQLi + SSTI markers in a
  single request, cutting the request count roughly threefold versus
  testing each vulnerability class separately.
- **Cookie support** (`-c`) for testing behind auth.
- **Live terminal dashboard** — ASCII logo, overall + current-endpoint
  progress bars, a rolling 10-line request log, and a live findings
  counter. Falls back to plain scrolling output with `-no-ui`.
- **Zero external Go dependencies** — standard library only.

## Installation

### Prerequisites

- [Go 1.22+](https://go.dev/dl/)
- Optional, for fuller URL collection in host mode (any/all can be skipped):
  - [`gau`](https://github.com/lc/gau)
  - [`katana`](https://github.com/projectdiscovery/katana)
  - [`waymore`](https://github.com/xnl-h4ck3r/waymore) — note: `reflx`
    invokes waymore with `--providers wayback,commoncrawl,otx,urlscan`, so
    VirusTotal is never queried even if you have it configured in your
    waymore `config.yml`.

### Build from source

```bash
git clone https://github.com/ashrafabdelrazik/reflx.git
cd reflx
go build -o reflx .
```

That produces a single `reflx` binary in the current directory. Move it
onto your `$PATH` if you'd like to call it from anywhere:

```bash
sudo mv reflx /usr/local/bin/
```

### Optional: install the URL-collection helpers

```bash
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
pip install waymore
```

`reflx` checks `$PATH` for each of these at runtime and just skips
whichever ones aren't installed — none of them are required to run the
tool.

## Quick start

```bash
# host mode — collect, dedupe, and test every endpoint found
./reflx -u example.com

# single-URL mode — test only this one endpoint
./reflx -u 'https://example.com/search?q=x'

# authenticated testing
./reflx -u example.com -c "session=abc123; role=admin"
```

## How it works

**Host mode** (`-u example.com`):

1. Collects URLs from the Wayback CDX API, plus `gau`/`katana`/`waymore` if
   present.
2. Keeps only URLs with query parameters.
3. Deduplicates to one representative URL per endpoint *shape* (see
   [Features](#features)).
4. Runs the test pass below against every deduped endpoint.

**Single-URL mode** (`-u 'https://example.com/search?q=x'`): skips
collection entirely and runs the test pass against just that one URL.

Mode is auto-detected from `-u` — anything containing `://` is treated as a
single URL, everything else as a bare host. Override with `-mode host` /
`-mode url` if needed.

**Test pass** (both modes), for every target URL:

5. Builds a parameter wordlist from params already on the URL, live form
   field names, JSON keys in the response, and a built-in default list —
   every URL parameter is always tested, not just wordlist filler.
6. Fires one combined XSS + SQLi + SSTI payload per parameter as both a GET
   query param and a POST form field. Any parameter the endpoint already
   requires (e.g. `id` in `game.php?id=1`) stays attached to every request
   so the page keeps working while a *different* parameter is being fuzzed.

### What "combined in one request" means

```
"'><script>/*XSSOK123456*/document.title='XSSOK123456'</script>' OR SLEEP(0)-- SQLIOK654321{{61*71}}${61*71}<%= 61*71 %>
```

- **XSS** — checks for the unescaped `document.title='XSSOK123456'`
  script-context reflection.
- **SQLi** — checks for DBMS error signatures (MySQL/Postgres/MSSQL/Oracle/
  SQLite). A second, separate syntax-breaking-only request (`'"\`)`) is also
  sent, in case a broken quote blanks the page before the other markers
  would render.
- **SSTI** (the reflected-math test) — sends two random two-digit numbers
  through three template syntaxes at once (`{{a*b}}`, `${a*b}`,
  `<%= a*b %>`, covering Jinja2/Twig, FreeMarker/Velocity, and ERB) and
  checks whether the *evaluated product* — e.g. `49` for `7*7` — shows up
  in the response. If it does, the input is being executed server-side.

## Live dashboard

`reflx` draws an in-place terminal dashboard by default:

- **overall** — deduped endpoints (host mode) or the single target (URL
  mode) fully tested.
- **current** — GET/POST × parameter cycle progress for whichever endpoint
  most recently had a request go out. Numerator and denominator are always
  tracked together per-endpoint, so this never exceeds 100% even at high
  `-t`; under concurrency it will visibly jump between endpoints as workers
  report in — use `-t 1` for a strictly linear trace.
- **requests sent** — a run-wide, monotonic request counter against the
  planned total so far, useful for confirming real throughput even while
  the overall bar looks "stuck" on large, slow endpoints.
- **rolling log** — the last 10 requests sent, full method + URL (and POST
  body), ready to reproduce a hit manually.
- **counter** — live XSS / SQLi / SSTI totals.

Pass `-no-ui` for plain scrolling output instead (useful when piping to a
file or running in CI).

## Full usage / flags

```
  -u string          target (required):
                        host mode:       example.com
                        single-URL mode: https://example.com/search?q=x
  -mode string        auto | host | url  (default "auto")
  -o string           output file (default "findings.txt")
  -t int               concurrent workers, host mode only (default 20)
  -timeout duration    per-request timeout (default 10s)
  -delay duration      delay between requests per worker (default 50ms)
  -max-urls int        cap on deduped endpoints tested in host mode (default 500, 0 = no cap)
  -max-params int      cap on parameters tested per endpoint (default 40, 0 = no cap)
  -c string            optional cookie header sent with every request, e.g. -c "session=abc123; role=admin"
  -k                   skip TLS verification (default true — most staging hosts need this)
  -no-ui               disable the live dashboard, print plain scrolling log lines instead
  -v                   verbose logging
```

More examples:

```bash
# host mode with a higher URL cap
./reflx -u example.com -max-urls 2000 -o example-findings.txt

# keep per-endpoint testing fast on JSON-heavy pages
./reflx -u example.com -max-params 20

# plain output, piped to a file
./reflx -u example.com -no-ui > run.log
```

## Output format

Each finding is one line, written to both stdout and the `-o` file:

```
[XSS][GET] https://example.com/profile/123?x=1  param=redirect  unescaped script-context reflection of unique marker
[SQLi][POST] https://example.com/search  param=q  DB error signature triggered by syntax-breaking payload
[SSTI][GET] https://example.com/render?tpl=x  param=tpl  input evaluated server-side: sent a*b, got 4331 back in response (candidate — verify engine)
```

Treat SSTI hits as **candidates** to verify manually — the evaluated-number
check can have false positives if that number legitimately appears
elsewhere on the page, though this is unlikely with random two-digit
inputs.

## Scope reminder

This tool sends live injection payloads (script tags, SQL syntax breaks,
template expressions) to every parameter it finds. Only point it at
hosts/URLs you own or have explicit written authorization to test.

## License

No license has been chosen yet for this repository — add one (e.g. MIT,
Apache-2.0) via GitHub's "Add file → Create new file → LICENSE" template
picker before accepting outside contributions.

## Author

[@ashrafabdelrazik](https://github.com/ashrafabdelrazik)
