package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// ============================= LIVE TERMINAL DASHBOARD =============================
//
// Redraws a fixed-height, in-place dashboard: ASCII logo, an overall progress
// bar (how many deduped endpoints have been fully tested), a current-test
// progress bar (how far through the GET/POST x param request cycle the
// endpoint currently being worked on is), a rolling 10-line log showing the
// full request URL each probe actually sent, and a live findings counter by
// class (XSS/SQLi/SSTI).
//
// Under concurrency (-t > 1) several workers are testing different endpoints
// at once; the "current test" bar reflects whichever request most recently
// went out, not any single worker in isolation — that's an intentional
// simplification rather than a multi-lane per-worker view. Use -t 1 for a
// perfectly linear one-endpoint-at-a-time trace, or -no-ui for a plain
// scrolling log if you're piping output to a file.

var dash = &dashboard{logMax: 10}

type dashLine struct {
	tag  string // GET / POST / XSS / SQLi / SSTI / INFO
	text string
}

type dashboard struct {
	mu sync.Mutex

	enabled bool
	started time.Time
	target  string
	mode    string // "host" or "url"

	overallCur, overallTotal int
	plannedRequests          int // sum of len(params)*4 across every endpoint started so far
	requestsSent             int // actual requests fired so far, run-wide

	curURL            string
	curStep, curTotal int

	logLines []dashLine
	logMax   int

	xss, sqli, ssti int

	drawn      bool
	stopTicker chan struct{}
}

const (
	dashAmber  = "\033[38;2;232;163;61m"
	dashDim    = "\033[38;2;124;135;126m"
	dashMute   = "\033[38;2;77;86;79m"
	dashWhite  = "\033[97m"
	dashCyan   = "\033[38;2;95;179;255m"
	dashGreen  = "\033[38;2;126;231;135m"
	dashRed    = "\033[38;2;255;107;107m"
	dashReset  = "\033[0m"
	cursorHide = "\033[?25l"
	cursorShow = "\033[?25h"
	clearToEnd = "\033[0J"
)

const dashLogo = `
██████╗ ███████╗███████╗██╗     ██╗  ██╗
██╔══██╗██╔════╝██╔════╝██║     ╚██╗██╔╝
██████╔╝█████╗  █████╗  ██║      ╚███╔╝
██╔══██╗██╔══╝  ██╔══╝  ██║      ██╔██╗
██║  ██║███████╗██║     ███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝`

// dashMaxLineWidth keeps every logical log line to one terminal row so the
// fixed header above it (logo/target/progress bars) never scrolls out of
// place from an unexpectedly wrapped line. See truncateVisible.
const dashMaxLineWidth = 100

func truncateVisible(s string, max int) string {
	if max < 1 {
		max = 1
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max == 1 {
		return string(r[:1])
	}
	return string(r[:max-1]) + "…"
}

// dashStart begins dashboard mode. target is the domain/URL being tested,
// mode is "host" or "url".
func dashStart(target, mode string, overallTotal int) {
	dash.mu.Lock()
	dash.enabled = true
	dash.started = time.Now()
	dash.target = target
	dash.mode = mode
	dash.overallTotal = overallTotal
	stop := make(chan struct{})
	dash.stopTicker = stop
	dash.mu.Unlock()

	fmt.Print(cursorHide)
	dash.render()
	go dash.tickElapsed(stop)
}

func (d *dashboard) tickElapsed(stop chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			d.render()
		case <-stop:
			return
		}
	}
}

// dashStop restores the cursor, stops the ticker, and leaves the final frame
// in place. Always call via defer right after dashStart.
func dashStop() {
	dash.mu.Lock()
	was := dash.enabled
	dash.enabled = false
	stop := dash.stopTicker
	dash.mu.Unlock()
	if was && stop != nil {
		close(stop)
	}
	if was {
		fmt.Print(cursorShow + "\n")
	}
}

// dashUpdateCurrent atomically sets the "current test" bar's URL, numerator,
// and denominator together in one call, and is also used to advance the
// aggregate request-progress counter used by dashRequestTotals. Each
// testEndpoint call tracks its own local step count and passes it in here —
// numerator and denominator always come from the same endpoint's own state,
// so the bar can never show something like 3414/276 (a step count from one
// worker's endpoint divided by a totally different endpoint's total, which
// is what a single shared global counter caused under concurrency).
func dashUpdateCurrent(url string, step, total int) {
	dash.mu.Lock()
	dash.curURL = url
	dash.curStep = step
	dash.curTotal = total
	dash.mu.Unlock()
	dash.render()
}

// dashBeginURL resets the current-test bar for a newly-started endpoint.
// totalSteps is normally len(params)*4 (GET combined, GET sql-only, POST
// combined, POST sql-only, per parameter). Also registers totalSteps against
// the run-wide request total so the overall bar's tooltip/label can report
// real throughput even while individual endpoints are still in flight.
func dashBeginURL(url string, totalSteps int) {
	dash.mu.Lock()
	dash.curURL = url
	dash.curStep = 0
	dash.curTotal = totalSteps
	dash.plannedRequests += totalSteps
	dash.mu.Unlock()
	dash.render()
}

// dashFinishURL marks one more endpoint as fully tested, advancing the
// overall progress bar.
func dashFinishURL() {
	dash.mu.Lock()
	dash.overallCur++
	dash.mu.Unlock()
	dash.render()
}

// dashLogRequest logs the exact URL/method that was just sent and bumps the
// run-wide "requests sent" counter, but does NOT touch the per-endpoint
// current-test counter — callers track their own local step count and call
// dashUpdateCurrent for that instead, since under concurrency this function
// gets called interleaved by many different endpoints' goroutines at once.
func dashLogRequest(method, fullURL string) {
	dash.mu.Lock()
	dash.requestsSent++
	if !dash.enabled {
		dash.mu.Unlock()
		fmt.Printf("[%s] %s\n", method, fullURL)
		return
	}
	dash.pushLogLocked(method, truncateVisible(fullURL, dashMaxLineWidth-6))
	dash.mu.Unlock()
	dash.render()
}

// dashLog writes a plain informational line (collection phase, errors, etc.)
func dashLog(text string) {
	dash.mu.Lock()
	if !dash.enabled {
		dash.mu.Unlock()
		fmt.Println(text)
		return
	}
	dash.pushLogLocked("INFO", truncateVisible(text, dashMaxLineWidth-6))
	dash.mu.Unlock()
	dash.render()
}

// dashFinding logs a colored finding line and bumps the relevant counter.
func dashFinding(kind, line string) {
	dash.mu.Lock()
	switch kind {
	case "XSS":
		dash.xss++
	case "SQLi":
		dash.sqli++
	case "SSTI":
		dash.ssti++
	}
	if !dash.enabled {
		dash.mu.Unlock()
		fmt.Println(line)
		return
	}
	dash.pushLogLocked(kind, truncateVisible(line, dashMaxLineWidth-6))
	dash.mu.Unlock()
	dash.render()
}

func (d *dashboard) pushLogLocked(tag, text string) {
	d.logLines = append(d.logLines, dashLine{tag, text})
	if len(d.logLines) > d.logMax {
		d.logLines = d.logLines[len(d.logLines)-d.logMax:]
	}
}

func colorForTag(tag string) string {
	switch tag {
	case "GET":
		return dashCyan
	case "POST":
		return dashAmber
	case "XSS", "SQLi", "SSTI":
		return dashRed
	case "INFO":
		return dashDim
	default:
		return dashDim
	}
}

func plainLogLine(tag, text string) string {
	c := colorForTag(tag)
	label := tag
	if label == "" {
		label = "INFO"
	}
	pad := 5 - len(label)
	if pad < 0 {
		pad = 0
	}
	return c + "[" + label + "]" + strings.Repeat(" ", pad) + dashReset + " " + text
}

// render draws the full fixed-height frame in place.
func (d *dashboard) render() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.enabled {
		return
	}

	var b strings.Builder

	b.WriteString(dashAmber)
	b.WriteString(dashLogo)
	b.WriteString(dashReset)
	b.WriteString("\n\n")

	elapsed := time.Duration(0)
	if !d.started.IsZero() {
		elapsed = time.Since(d.started).Round(time.Second)
	}
	b.WriteString(fmt.Sprintf("%starget:%s %s%s%s  %smode:%s %s%s%s  %selapsed:%s %s\n",
		dashDim, dashReset, dashWhite, truncateVisible(d.target, 40), dashReset,
		dashDim, dashReset, dashWhite, d.mode, dashReset,
		dashDim, dashReset, elapsed))
	b.WriteString("\n")

	b.WriteString(dashDim + "overall " + dashReset + d.barLine(d.overallCur, d.overallTotal, "endpoints tested") + "\n")
	b.WriteString(dashDim + "current " + dashReset + d.barLine(d.curStep, d.curTotal, truncateVisible(d.curURL, 40)) + "\n")
	b.WriteString(fmt.Sprintf("%srequests sent:%s %s%d%s%s / ~%d planned so far (grows as more endpoints start)%s\n",
		dashDim, dashReset, dashWhite, d.requestsSent, dashReset, dashDim, d.plannedRequests, dashReset))
	b.WriteString("\n")

	for i := 0; i < d.logMax; i++ {
		idx := len(d.logLines) - d.logMax + i
		if idx >= 0 {
			ln := d.logLines[idx]
			b.WriteString(plainLogLine(ln.tag, ln.text))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")

	b.WriteString(fmt.Sprintf("%sXSS%s %d   %sSQLi%s %d   %sSSTI%s %d   %stotal%s %d\n",
		dashRed, dashReset, d.xss,
		dashRed, dashReset, d.sqli,
		dashRed, dashReset, d.ssti,
		dashWhite, dashReset, d.xss+d.sqli+d.ssti))

	frame := b.String()
	frameLines := strings.Count(frame, "\n")

	if d.drawn {
		fmt.Printf("\033[%dA", frameLines)
	}
	fmt.Print(clearToEnd)
	fmt.Print(frame)
	d.drawn = true
}

func (d *dashboard) barLine(current, total int, label string) string {
	const barLength = 30
	progress := 0.0
	if total > 0 {
		progress = float64(current) / float64(total)
	}
	if progress > 1 {
		progress = 1
	}
	filled := int(progress * float64(barLength))
	if filled > barLength {
		filled = barLength
	}
	bar := dashGreen + strings.Repeat("█", filled) + dashMute + strings.Repeat("-", barLength-filled) + dashReset
	percent := int(progress * 100)
	return fmt.Sprintf("[%s] %s%3d%%%s (%d/%d) %s%s%s", bar, dashDim, percent, dashReset, current, total, dashDim, label, dashReset)
}
