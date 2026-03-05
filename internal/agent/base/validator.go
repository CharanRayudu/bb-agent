package base

import (
	"context"
	"fmt"
	"strings"
)

// VisualValidator handles multi-modal confirmation of findings.
type VisualValidator struct{}

// NewVisualValidator creates a new validator instance.
func NewVisualValidator() *VisualValidator {
	return &VisualValidator{}
}

// ValidateXSS confirms an XSS vulnerability by reaching the page in a real browser.
func (v *VisualValidator) ValidateXSS(ctx context.Context, targetURL string, param string, payload string, isPOST bool) (bool, string, string, error) {
	opts := DefaultBrowserOptions()

	var metadata *BrowserMetadata
	var err error

	if isPOST {
		data := map[string]string{param: payload}
		metadata, err = RunHeadlessPOST(ctx, targetURL, data, opts)
	} else {
		sep := "?"
		if strings.Contains(targetURL, "?") {
			sep = "&"
		}
		testURL := fmt.Sprintf("%s%s%s=%s", targetURL, sep, param, payload)
		metadata, err = RunHeadless(ctx, testURL, opts)
	}

	if err != nil {
		return false, "", "", err
	}

	if metadata.AlertDetected {
		return true, "Confirmed: Alert triggered in browser", metadata.ScreenshotPath, nil
	}

	return false, "Not confirmed: No alert or visual reflection detected", metadata.ScreenshotPath, nil
}

// SpecialistNameToValidationType maps a specialist ID to a validation strategy.
func SpecialistNameToValidationType(name string) string {
	switch name {
	case "xss", "csti":
		return "browser_alert"
	case "sqli":
		return "timing_or_error"
	case "ssrf":
		return "oob_callback"
	default:
		return "basic_reflection"
	}
}
