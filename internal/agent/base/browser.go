package base

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

var (
	ErrBrowserUnavailable = errors.New("browser automation unavailable")
	browserDisabled       atomic.Bool
)

func shouldIgnoreBrowserErrorMessage(msg string) bool {
	lower := strings.ToLower(strings.TrimSpace(msg))
	return strings.Contains(lower, "could not unmarshal event") &&
		strings.Contains(lower, "cookiepartitionkey")
}

func browserErrorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if shouldIgnoreBrowserErrorMessage(msg) {
		return
	}
	log.Printf("[browser] %s", msg)
}

// BrowserMetadata contains information about a browser session's results.
type BrowserMetadata struct {
	ScreenshotPath string
	AlertDetected  bool
	AlertText      string
	Title          string
	URL            string
	ConsoleLogs    []string
	Performance    map[string]interface{}
}

// BrowserOptions configures the headless browser behavior.
type BrowserOptions struct {
	Timeout   time.Duration
	WaitUntil string // domcontentloaded, networkidle, etc.
	Width     int
	Height    int
	Proxy     string
	UserAgent string
	Headers   map[string]string
}

// DefaultBrowserOptions returns standard settings for vulnerability validation.
func DefaultBrowserOptions() BrowserOptions {
	return BrowserOptions{
		Timeout:   15 * time.Second,
		WaitUntil: "networkidle",
		Width:     1280,
		Height:    720,
	}
}

func BrowserAvailable() bool {
	return !browserDisabled.Load()
}

func DisableBrowserAutomation() {
	browserDisabled.Store(true)
}

func ResetBrowserAutomation() {
	browserDisabled.Store(false)
}

func IsBrowserUnavailableError(err error) bool {
	return errors.Is(err, ErrBrowserUnavailable)
}

func shouldDisableBrowser(err error) bool {
	if err == nil {
		return false
	}

	lower := strings.ToLower(err.Error())
	indicators := []string{
		"cookiepartitionkey",
		"chrome failed to start",
		"failed to start",
		"browser process exited",
		"exec: \"google-chrome\"",
		"exec: \"chromium\"",
		"exec: \"chromium-browser\"",
		"chrome not reachable",
		"websocket url timeout reached",
		"target closed",
	}

	for _, indicator := range indicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}

	return false
}

func normalizeBrowserError(err error) error {
	if err == nil {
		return nil
	}
	if shouldDisableBrowser(err) {
		DisableBrowserAutomation()
		return fmt.Errorf("%w: %v", ErrBrowserUnavailable, err)
	}
	return err
}

// RunHeadless executes a browser task and returns metadata.
func RunHeadless(ctx context.Context, targetURL string, opts BrowserOptions) (*BrowserMetadata, error) {
	if !BrowserAvailable() {
		return nil, ErrBrowserUnavailable
	}

	if opts.Timeout == 0 {
		opts = DefaultBrowserOptions()
	}

	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.NoSandbox,
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.WindowSize(opts.Width, opts.Height),
	)

	if opts.Proxy != "" {
		allocOpts = append(allocOpts, chromedp.ProxyServer(opts.Proxy))
	}
	if opts.UserAgent != "" {
		allocOpts = append(allocOpts, chromedp.UserAgent(opts.UserAgent))
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, allocOpts...)
	defer cancelAlloc()

	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx, chromedp.WithErrorf(browserErrorf))
	defer cancelBrowser()

	timeoutCtx, cancelTimeout := context.WithTimeout(browserCtx, opts.Timeout)
	defer cancelTimeout()

	metadata := &BrowserMetadata{
		ConsoleLogs: []string{},
	}

	chromedp.ListenTarget(timeoutCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *page.EventJavascriptDialogOpening:
			metadata.AlertDetected = true
			metadata.AlertText = e.Message
			go func() {
				chromedp.Run(browserCtx, page.HandleJavaScriptDialog(true))
			}()
		case *runtime.EventConsoleAPICalled:
			for _, arg := range e.Args {
				metadata.ConsoleLogs = append(metadata.ConsoleLogs, fmt.Sprintf("%v", arg.Value))
			}
		}
	})

	var buf []byte
	err := chromedp.Run(timeoutCtx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(2*time.Second),
		chromedp.Title(&metadata.Title),
		chromedp.Location(&metadata.URL),
		chromedp.FullScreenshot(&buf, 90),
	)

	if err != nil && err != context.DeadlineExceeded {
		return nil, fmt.Errorf("browser run failed: %w", normalizeBrowserError(err))
	}

	if len(buf) > 0 {
		path, _ := saveScreenshot(buf)
		metadata.ScreenshotPath = path
	}

	return metadata, nil
}

// CrawlResults contains discovered elements from a headless crawl
type CrawlResults struct {
	Links  []string `json:"links"`
	Inputs []string `json:"inputs"`
}

// RunCrawl executes a discovery-focused browser task
func RunCrawl(ctx context.Context, targetURL string, opts BrowserOptions) (*CrawlResults, error) {
	if !BrowserAvailable() {
		return nil, ErrBrowserUnavailable
	}

	if opts.Timeout == 0 {
		opts = DefaultBrowserOptions()
		opts.Timeout = 30 * time.Second
	}

	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.NoSandbox,
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.WindowSize(opts.Width, opts.Height),
	)

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, allocOpts...)
	defer cancelAlloc()

	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx, chromedp.WithErrorf(browserErrorf))
	defer cancelBrowser()

	timeoutCtx, cancelTimeout := context.WithTimeout(browserCtx, opts.Timeout)
	defer cancelTimeout()

	results := &CrawlResults{}
	err := chromedp.Run(timeoutCtx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(3*time.Second),
		chromedp.Evaluate(`
			(function() {
				let result = {links: [], inputs: []};
				document.querySelectorAll('a').forEach(a => {
					if (a.href) result.links.push(a.href);
				});
				document.querySelectorAll('input, button, textarea, select').forEach(i => {
					let name = i.name || i.id || i.placeholder || i.innerText || i.tagName;
					if (name && name.length < 100) result.inputs.push(name.trim());
				});
				return result;
			})()
		`, results),
	)

	if err != nil {
		return nil, normalizeBrowserError(err)
	}

	return results, nil
}

// RunHeadlessPOST simulates a form submission
func RunHeadlessPOST(ctx context.Context, actionURL string, data map[string]string, opts BrowserOptions) (*BrowserMetadata, error) {
	formHTML := `<html><body onload="document.forms[0].submit()">`
	formHTML += fmt.Sprintf(`<form method="POST" action="%s">`, actionURL)
	for k, v := range data {
		formHTML += fmt.Sprintf(`<input type="hidden" name="%s" value='%s'>`, k, v)
	}
	formHTML += `</form></body></html>`

	dataURL := fmt.Sprintf("data:text/html;base64,%s", base64.StdEncoding.EncodeToString([]byte(formHTML)))
	return RunHeadless(ctx, dataURL, opts)
}

func saveScreenshot(buf []byte) (string, error) {
	dir := "logs/screenshots"
	os.MkdirAll(dir, 0755)
	filename := fmt.Sprintf("ss_%d.png", time.Now().UnixNano())
	path := filepath.Join(dir, filename)
	err := os.WriteFile(path, buf, 0644)
	return filename, err
}
