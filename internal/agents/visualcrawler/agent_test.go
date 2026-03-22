package visualcrawler

import "testing"

func TestShouldKeepDiscoveredLink(t *testing.T) {
	target := "https://example.com/app"

	tests := []struct {
		name       string
		discovered string
		want       bool
	}{
		{name: "same host", discovered: "https://example.com/dashboard", want: true},
		{name: "subdomain", discovered: "https://api.example.com/v1/users", want: true},
		{name: "different host", discovered: "https://github.com/topics/appsec", want: false},
		{name: "different suffix", discovered: "https://badexample.com", want: false},
		{name: "non http scheme", discovered: "javascript:void(0)", want: false},
		{name: "mailto scheme", discovered: "mailto:test@example.com", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldKeepDiscoveredLink(target, tt.discovered); got != tt.want {
				t.Fatalf("shouldKeepDiscoveredLink(%q, %q) = %v, want %v", target, tt.discovered, got, tt.want)
			}
		})
	}
}
