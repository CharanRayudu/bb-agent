package base

import (
	"context"
	"errors"
	"testing"
)

func TestRunCrawlReturnsBrowserUnavailableWhenDisabled(t *testing.T) {
	previous := browserDisabled.Load()
	browserDisabled.Store(true)
	defer browserDisabled.Store(previous)

	_, err := RunCrawl(context.Background(), "http://example.com", DefaultBrowserOptions())
	if !errors.Is(err, ErrBrowserUnavailable) {
		t.Fatalf("expected ErrBrowserUnavailable, got %v", err)
	}
}

func TestResetBrowserAutomationReEnablesBrowser(t *testing.T) {
	previous := browserDisabled.Load()
	browserDisabled.Store(true)
	defer browserDisabled.Store(previous)

	ResetBrowserAutomation()

	if !BrowserAvailable() {
		t.Fatal("expected browser automation to be re-enabled after reset")
	}
}

func TestShouldIgnoreBrowserErrorMessageSuppressesCookiePartitionNoise(t *testing.T) {
	msg := `could not unmarshal event: json: cannot unmarshal JSON string into Go network.CookiePartitionKey within "/cookiePartitionKey"`
	if !shouldIgnoreBrowserErrorMessage(msg) {
		t.Fatal("expected cookie partition decoder noise to be suppressed")
	}
}
