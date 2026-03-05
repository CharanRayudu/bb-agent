package agent

import (
	"fmt"
	"strings"
	"sync"
)

// AdaptiveRateLimiter dynamically adjusts scan speed based on WAF/server feedback
type AdaptiveRateLimiter struct {
	mu            sync.RWMutex
	currentRate   float64 // requests per second
	maxRate       float64 // ceiling (original rate)
	minRate       float64 // floor (never go below this)
	wafDetected   bool
	throttleCount int
}

// NewAdaptiveRateLimiter creates a rate limiter with a starting rate
func NewAdaptiveRateLimiter(initialRate float64) *AdaptiveRateLimiter {
	return &AdaptiveRateLimiter{
		currentRate: initialRate,
		maxRate:     initialRate,
		minRate:     1.0, // Never slower than 1 req/s
	}
}

// DetectThrottling analyzes tool output for WAF/rate-limiting indicators
func (r *AdaptiveRateLimiter) DetectThrottling(output string) bool {
	lower := strings.ToLower(output)

	wafIndicators := []string{
		"429",
		"rate limit",
		"too many requests",
		"access denied",
		"cloudflare",
		"akamai",
		"incapsula",
		"sucuri",
		"mod_security",
		"waf",
		"blocked",
		"captcha",
		"challenge",
		"403 forbidden",
		"request rate too large",
		"slow down",
	}

	for _, indicator := range wafIndicators {
		if strings.Contains(lower, indicator) {
			r.mu.Lock()
			r.wafDetected = true
			r.throttleCount++
			r.mu.Unlock()
			return true
		}
	}
	return false
}

// SlowDown halves the current rate (minimum: minRate)
func (r *AdaptiveRateLimiter) SlowDown() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.currentRate = r.currentRate / 2
	if r.currentRate < r.minRate {
		r.currentRate = r.minRate
	}
	return r.currentRate
}

// SpeedUp increases rate by 25% (capped at maxRate)
func (r *AdaptiveRateLimiter) SpeedUp() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.currentRate = r.currentRate * 1.25
	if r.currentRate > r.maxRate {
		r.currentRate = r.maxRate
	}
	return r.currentRate
}

// CurrentRate returns the current rate (thread-safe)
func (r *AdaptiveRateLimiter) CurrentRate() float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.currentRate
}

// IsWAFDetected returns whether a WAF has been detected
func (r *AdaptiveRateLimiter) IsWAFDetected() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.wafDetected
}

// GetRecommendedFlags returns tool-specific rate-limiting flags based on current rate
func (r *AdaptiveRateLimiter) GetRecommendedFlags(tool string) string {
	r.mu.RLock()
	rate := r.currentRate
	r.mu.RUnlock()

	rateInt := int(rate)
	if rateInt < 1 {
		rateInt = 1
	}

	toolLower := strings.ToLower(tool)

	switch {
	case strings.Contains(toolLower, "nuclei"):
		return strings.Join([]string{
			"-rl", intToStr(rateInt),
			"-c", intToStr(max(1, rateInt/2)),
		}, " ")
	case strings.Contains(toolLower, "ffuf"):
		return strings.Join([]string{
			"-rate", intToStr(rateInt),
			"-t", intToStr(max(1, rateInt)),
		}, " ")
	case strings.Contains(toolLower, "gobuster"), strings.Contains(toolLower, "feroxbuster"):
		return strings.Join([]string{
			"--threads", intToStr(max(1, rateInt)),
		}, " ")
	case strings.Contains(toolLower, "sqlmap"):
		return strings.Join([]string{
			"--threads=" + intToStr(max(1, rateInt/5)),
			"--delay=1",
		}, " ")
	case strings.Contains(toolLower, "curl"):
		return "" // curl doesn't need rate flags
	case strings.Contains(toolLower, "nmap"):
		if rateInt <= 5 {
			return "-T2" // Polite
		}
		return "-T3" // Normal
	default:
		return ""
	}
}

// InjectRateFlags modifies a command string to include rate-limiting flags if needed
func (r *AdaptiveRateLimiter) InjectRateFlags(command string) string {
	if !r.IsWAFDetected() {
		return command
	}

	flags := r.GetRecommendedFlags(command)
	if flags == "" {
		return command
	}

	// Don't double-inject
	if strings.Contains(command, "-rl ") || strings.Contains(command, "-rate ") || strings.Contains(command, "--threads") {
		return command
	}

	return command + " " + flags
}

func intToStr(n int) string {
	return fmt.Sprintf("%d", n)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
