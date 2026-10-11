package decision

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const systemOnePath = "/providers/microsoft/v1/systemone"

// APIError is a non-2xx response from the decision service.
type APIError struct {
	Status int
	Detail string
	Body   string
}

func (e *APIError) Error() string {
	if e == nil {
		return "decision API error"
	}
	detail := strings.TrimSpace(e.Detail)
	if detail == "" {
		detail = strings.TrimSpace(e.Body)
	}
	if detail == "" {
		return fmt.Sprintf("decision API status %d", e.Status)
	}
	return fmt.Sprintf("decision API status %d: %s", e.Status, detail)
}

// FoundryClient calls Microsoft Foundry's System One route.
type FoundryClient struct {
	Endpoint   string
	Deployment string
	APIKey     string
	Timeout    time.Duration
	HTTP       *http.Client
}

// NewFoundryClient builds a client. The API key is not logged or stored in errors.
func NewFoundryClient(endpoint, deployment, apiKey string, timeout time.Duration) *FoundryClient {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &FoundryClient{
		Endpoint:   strings.TrimRight(strings.TrimSpace(endpoint), "/"),
		Deployment: strings.TrimSpace(deployment),
		APIKey:     strings.TrimSpace(apiKey),
		Timeout:    timeout,
		HTTP:       &http.Client{Timeout: timeout},
	}
}

// Decide posts model, state, and questions to the Foundry System One route.
func (c *FoundryClient) Decide(ctx context.Context, req Request) (Response, error) {
	if c == nil || c.Endpoint == "" {
		return Response{}, fmt.Errorf("foundry endpoint is not configured")
	}
	if c.APIKey == "" {
		return Response{}, fmt.Errorf("foundry API key is not configured")
	}
	if len(req.Questions) == 0 {
		return Response{}, fmt.Errorf("decision request has no questions")
	}
	model := strings.TrimSpace(req.Model)
	if model == "" {
		model = c.Deployment
	}
	if model == "" {
		return Response{}, fmt.Errorf("foundry deployment name is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}

	payload := struct {
		Model     string              `json:"model"`
		State     any                 `json:"state"`
		Questions map[string]Question `json:"questions"`
	}{Model: model, State: req.State, Questions: req.Questions}
	body, err := json.Marshal(payload)
	if err != nil {
		return Response{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpointURL(), bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("api-key", c.APIKey)

	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	started := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return Response{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Response{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Response{}, &APIError{Status: resp.StatusCode, Detail: errorDetail(raw), Body: string(raw)}
	}
	parsed, err := decodeResponse(raw)
	if err != nil {
		return Response{}, err
	}
	parsed.Latency = time.Since(started)
	return parsed, nil
}

func (c *FoundryClient) endpointURL() string {
	if strings.Contains(c.Endpoint, systemOnePath) {
		return c.Endpoint
	}
	return c.Endpoint + systemOnePath
}

func errorDetail(raw []byte) string {
	var body struct {
		Detail  json.RawMessage `json:"detail"`
		Message string          `json:"message"`
		Error   struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return ""
	}
	if body.Error.Message != "" {
		return body.Error.Message
	}
	if body.Message != "" {
		return body.Message
	}
	if len(body.Detail) == 0 {
		return ""
	}
	var text string
	if err := json.Unmarshal(body.Detail, &text); err == nil {
		return text
	}
	return string(body.Detail)
}

func decodeResponse(raw []byte) (Response, error) {
	var wire struct {
		Model   string                     `json:"model"`
		Answers map[string]json.RawMessage `json:"answers"`
		Usage   struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return Response{}, fmt.Errorf("decode decision response: %w", err)
	}
	if len(wire.Answers) == 0 {
		return Response{}, fmt.Errorf("decision response has no answers")
	}
	out := Response{
		Model:   wire.Model,
		Answers: make(map[string]Answer, len(wire.Answers)),
		Usage:   Usage{InputTokens: wire.Usage.InputTokens, OutputTokens: wire.Usage.OutputTokens},
	}
	for id, rawAnswer := range wire.Answers {
		answer, err := decodeAnswer(rawAnswer)
		if err != nil {
			return Response{}, fmt.Errorf("answer %s: %w", id, err)
		}
		out.Answers[id] = answer
	}
	return out, nil
}

func decodeAnswer(raw json.RawMessage) (Answer, error) {
	var kind struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &kind); err != nil {
		return Answer{}, err
	}
	switch kind.Type {
	case TypeNoul:
		var body struct {
			Noul float64 `json:"noul"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return Answer{}, err
		}
		value := body.Noul
		return Answer{Type: TypeNoul, Noul: &value}, nil
	case TypeChoice:
		var body struct {
			Choice        string             `json:"choice"`
			Confidence    float64            `json:"confidence"`
			Probabilities map[string]float64 `json:"probabilities"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return Answer{}, err
		}
		if body.Choice == "" {
			return Answer{}, fmt.Errorf("choice answer is empty")
		}
		confidence := body.Confidence
		return Answer{Type: TypeChoice, Choice: body.Choice, Confidence: &confidence, Probabilities: body.Probabilities}, nil
	case TypeScore:
		var body struct {
			Score         float64            `json:"score"`
			Confidence    float64            `json:"confidence"`
			Legend        map[string]string  `json:"legend"`
			Probabilities map[string]float64 `json:"probabilities"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return Answer{}, err
		}
		score := body.Score
		confidence := body.Confidence
		return Answer{Type: TypeScore, Score: &score, Confidence: &confidence, Legend: body.Legend, Probabilities: body.Probabilities}, nil
	default:
		return Answer{}, fmt.Errorf("unknown answer type %q", kind.Type)
	}
}
