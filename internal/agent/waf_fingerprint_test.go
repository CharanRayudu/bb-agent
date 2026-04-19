package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestWAFBypassPayloads_AllVendors verifies every known vendor returns at least one bypass variant.
func TestWAFBypassPayloads_AllVendors(t *testing.T) {
	vendors := []WAFVendor{
		WAFCloudflare, WAFAkamai, WAFAWSShield, WAFModSecurity,
		WAFWordFence, WAFSucuri, WAFIncapsula, WAFUnknown,
	}
	base := `' OR 1=1-- -`
	for _, v := range vendors {
		variants := WAFBypassPayloads(v, base)
		if len(variants) == 0 {
			t.Errorf("vendor %q returned zero bypass variants", v)
		}
		for i, variant := range variants {
			if variant == "" {
				t.Errorf("vendor %q: bypass variant[%d] is empty string", v, i)
			}
		}
	}
}

// TestWAFBypassPayloads_CloudflareTransforms verifies Cloudflare-specific transforms.
func TestWAFBypassPayloads_CloudflareTransforms(t *testing.T) {
	variants := WAFBypassPayloads(WAFCloudflare, `' OR 1=1-- -`)
	hasEncoded := false
	hasCommented := false
	for _, v := range variants {
		if strings.Contains(v, "%27") {
			hasEncoded = true
		}
		if strings.Contains(v, "/**/") {
			hasCommented = true
		}
	}
	if !hasEncoded {
		t.Error("Cloudflare bypass should include URL-encoded quote (%27)")
	}
	if !hasCommented {
		t.Error("Cloudflare bypass should include comment-insertion (/**/) variant")
	}
}

// TestWAFBypassPayloads_ModSecurityCommentVersion verifies ModSecurity version-comment bypass.
func TestWAFBypassPayloads_ModSecurityCommentVersion(t *testing.T) {
	variants := WAFBypassPayloads(WAFModSecurity, `' OR 1=1-- -`)
	found := false
	for _, v := range variants {
		if strings.Contains(v, "/*!OR*/") || strings.Contains(v, "%09") || strings.Contains(v, "0x27") {
			found = true
		}
	}
	if !found {
		t.Error("ModSecurity bypass should include version-comment or tab/hex encoding")
	}
}

// TestWAFBypassPayloads_EmptyBase verifies empty base payload produces non-empty variants.
func TestWAFBypassPayloads_EmptyBase(t *testing.T) {
	variants := WAFBypassPayloads(WAFCloudflare, "")
	if len(variants) == 0 {
		t.Error("empty base payload should still produce bypass variant list")
	}
}

// TestWAFBypassSets_Coverage verifies all vendors have non-empty bypass technique sets.
func TestWAFBypassSets_Coverage(t *testing.T) {
	vendors := []WAFVendor{
		WAFCloudflare, WAFAkamai, WAFAWSShield, WAFModSecurity,
		WAFWordFence, WAFSucuri, WAFIncapsula, WAFUnknown,
	}
	for _, v := range vendors {
		sets := wafBypassSets(v)
		if len(sets) == 0 {
			t.Errorf("vendor %q has no bypass technique sets", v)
		}
	}
}

// TestFingerprintWAF_Cloudflare verifies a server with CF-Ray header is detected as Cloudflare.
func TestFingerprintWAF_Cloudflare(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Ray", "abc123-IAD")
		w.Header().Set("CF-Cache-Status", "DYNAMIC")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("access denied by cloudflare"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := FingerprintWAF(ctx, srv.URL)
	if result.Vendor != WAFCloudflare {
		t.Errorf("expected WAFCloudflare, got %q (confidence %.2f)", result.Vendor, result.Confidence)
	}
	if result.Confidence < 0.5 {
		t.Errorf("Cloudflare detection confidence %.2f too low", result.Confidence)
	}
	if len(result.BypassSets) == 0 {
		t.Error("Cloudflare result should include bypass sets")
	}
}

// TestFingerprintWAF_Sucuri verifies a server with Sucuri headers is detected.
func TestFingerprintWAF_Sucuri(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Sucuri-ID", "12345")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("access denied - sucuri website firewall"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := FingerprintWAF(ctx, srv.URL)
	if result.Vendor != WAFSucuri {
		t.Errorf("expected WAFSucuri, got %q", result.Vendor)
	}
}

// TestFingerprintWAF_None verifies a clean 200 server returns WAFNone with low confidence.
func TestFingerprintWAF_None(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("welcome"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := FingerprintWAF(ctx, srv.URL)
	if result.Vendor != WAFNone {
		t.Errorf("expected WAFNone for clean server, got %q", result.Vendor)
	}
}

// TestFingerprintWAF_UnknownWAF verifies a 403 with no vendor headers returns WAFUnknown.
func TestFingerprintWAF_UnknownWAF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := FingerprintWAF(ctx, srv.URL)
	if result.Vendor != WAFUnknown {
		t.Errorf("expected WAFUnknown for vanilla 403, got %q", result.Vendor)
	}
	if result.Confidence < 0.3 {
		t.Errorf("WAFUnknown confidence %.2f too low", result.Confidence)
	}
}

// TestFlattenHeaders verifies flattenHeaders joins all header key/values.
func TestFlattenHeaders(t *testing.T) {
	h := http.Header{
		"Cf-Ray":          []string{"abc123"},
		"X-Custom-Header": []string{"foo", "bar"},
	}
	flat := flattenHeaders(h)
	if !strings.Contains(flat, "cf-ray") {
		t.Error("expected cf-ray in flattened headers")
	}
	if !strings.Contains(flat, "abc123") {
		t.Error("expected header value abc123 in flattened headers")
	}
}
