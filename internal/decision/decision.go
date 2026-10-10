// Package decision selects among typed options. It does not generate prose.
package decision

import (
	"context"
	"time"
)

const (
	TypeNoul   = "noul"
	TypeChoice = "choice"
	TypeScore  = "score"

	SourceModel = "decision-1"
	SourceRules = "rules"
)

// Provider evaluates application state and returns typed answers.
// A generative chat model is not a Provider.
type Provider interface {
	Decide(ctx context.Context, req Request) (Response, error)
}

// Request is a System One evaluation.
type Request struct {
	Model     string
	State     any
	Questions map[string]Question
}

// Question is one noul, choice, or score item.
type Question struct {
	Type         string `json:"type"`
	Instructions any    `json:"instructions,omitempty"`
	Criteria     any    `json:"criteria,omitempty"`
}

// Response is the typed result of one evaluation.
type Response struct {
	Model   string
	Answers map[string]Answer
	Usage   Usage
	Latency time.Duration
}

// Usage counts tokens reported by the service.
type Usage struct {
	InputTokens  int
	OutputTokens int
}

// Answer is one typed result. Unused fields stay at their zero value.
type Answer struct {
	Type          string
	Noul          *float64
	Choice        string
	Score         *float64
	Confidence    *float64
	Probabilities map[string]float64
	Legend        map[string]string
}

// Confident reports whether a choice or score answer meets the threshold.
// A noul answer is confident outside the uncertain band around 0.5.
func (a Answer) Confident(min float64) bool {
	if min <= 0 {
		min = 0.55
	}
	switch a.Type {
	case TypeChoice, TypeScore:
		if a.Confidence == nil {
			return false
		}
		return *a.Confidence >= min
	case TypeNoul:
		if a.Noul == nil {
			return false
		}
		distance := *a.Noul - 0.5
		if distance < 0 {
			distance = -distance
		}
		return distance >= (min / 2)
	default:
		return false
	}
}
