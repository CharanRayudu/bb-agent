package llm

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/bb-agent/mirage/internal/models"
)

// API endpoints
const (
	// ChatGPT backend endpoint — used by Codex CLI with ChatGPT OAuth
	codexResponsesURL = "https://chatgpt.com/backend-api/codex/responses"
	// Standard OpenAI API endpoint — used with API keys
	openAICompletionsURL = "https://api.openai.com/v1/chat/completions"
)

// AuthMode represents how the provider authenticates
type AuthMode string

const (
	AuthModeAPIKey     AuthMode = "api_key"
	AuthModeCodexOAuth AuthMode = "codex_oauth"
)

// OpenAIProvider implements LLM Provider using the OpenAI API
// Supports both API key and Codex CLI OAuth authentication
type OpenAIProvider struct {
	authMode    AuthMode
	apiKey      string              // used when authMode == AuthModeAPIKey
	codexAuth   *CodexTokenProvider // used when authMode == AuthModeCodexOAuth
	model       string
	temperature float64
	httpClient  *http.Client
}

// NewOpenAIProvider creates a provider using a raw API key
func NewOpenAIProvider(apiKey, model string, temperature float64) *OpenAIProvider {
	return &OpenAIProvider{
		authMode:    AuthModeAPIKey,
		apiKey:      apiKey,
		model:       model,
		temperature: temperature,
		httpClient:  &http.Client{},
	}
}

// NewOpenAIProviderWithCodex creates a provider using Codex CLI OAuth tokens
func NewOpenAIProviderWithCodex(codexAuth *CodexTokenProvider, model string, temperature float64) *OpenAIProvider {
	return &OpenAIProvider{
		authMode:    AuthModeCodexOAuth,
		codexAuth:   codexAuth,
		model:       model,
		temperature: temperature,
		httpClient:  &http.Client{},
	}
}

func (o *OpenAIProvider) Name() string {
	if o.authMode == AuthModeCodexOAuth {
		return "openai (codex oauth)"
	}
	return "openai (api key)"
}

// getAuthToken returns the appropriate Bearer token based on auth mode
func (o *OpenAIProvider) getAuthToken() (string, error) {
	switch o.authMode {
	case AuthModeAPIKey:
		return o.apiKey, nil
	case AuthModeCodexOAuth:
		return o.codexAuth.GetToken()
	default:
		return "", fmt.Errorf("unknown auth mode: %s", o.authMode)
	}
}

// Complete sends a request to the appropriate API endpoint
func (o *OpenAIProvider) Complete(req CompletionRequest) (*CompletionResponse, error) {
	if o.authMode == AuthModeCodexOAuth {
		return o.completeViaCodexResponses(req)
	}
	return o.completeViaChatCompletions(req)
}

// ============================================================
// Codex CLI / ChatGPT Responses API
// Endpoint: https://chatgpt.com/backend-api/codex/responses
// ============================================================

// Responses API request structures
type responsesRequest struct {
	Model        string             `json:"model"`
	Instructions string             `json:"instructions"`
	Input        []responsesMessage `json:"input"`
	Tools        []responsesTool    `json:"tools,omitempty"`
	Store        bool               `json:"store"`
	Stream       bool               `json:"stream"`
}

type responsesMessage struct {
	Role    string  `json:"role,omitempty"`
	Content *string `json:"content,omitempty"`
	// For function_call and function_call_output types
	Type      string `json:"type,omitempty"`
	CallID    string `json:"call_id,omitempty"`
	Name      string `json:"name,omitempty"`
	Output    string `json:"output,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

type responsesTool struct {
	Type        string                 `json:"type"`
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

// Responses API response structures
type responsesAPIResponse struct {
	ID     string            `json:"id"`
	Output []responsesOutput `json:"output"`
	Usage  *responsesUsage   `json:"usage,omitempty"`
	Error  *responsesError   `json:"error,omitempty"`
}

type responsesOutput struct {
	Type string `json:"type"`
	// For "message" type
	Content []responsesContent `json:"content,omitempty"`
	Role    string             `json:"role,omitempty"`
	// For "function_call" type
	ID        string `json:"id,omitempty"`
	CallID    string `json:"call_id,omitempty"`
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

type responsesContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type responsesUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

type responsesError struct {
	Message string `json:"message"`
	Code    string `json:"code"`
}

func (o *OpenAIProvider) completeViaCodexResponses(req CompletionRequest) (*CompletionResponse, error) {
	token, err := o.getAuthToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get Codex auth token: %w", err)
	}

	// Build input messages for the Responses API
	var input []responsesMessage
	var instructions string
	for _, m := range req.Messages {
		if m.Role == "system" || m.Role == "developer" {
			// System prompt goes into the top-level "instructions" field
			instructions = m.Content
			continue
		}
		if m.Role == "tool" {
			// Tool results use a special format in Responses API
			input = append(input, responsesMessage{
				Type:   "function_call_output",
				CallID: m.ToolCallID,
				Output: m.Content,
			})
		} else {
			role := m.Role
			if role == "system" {
				role = "developer" // Responses API uses "developer" instead of "system"
			}
			input = append(input, responsesMessage{
				Role:    role,
				Content: &m.Content,
			})
			// If this assistant message had tool calls, emit them as function_call items
			for _, tc := range m.ToolCalls {
				input = append(input, responsesMessage{
					Type:      "function_call",
					CallID:    tc.ID,
					Name:      tc.Name,
					Arguments: tc.Arguments,
				})
			}
		}
	}

	// Build tools
	var tools []responsesTool
	for _, t := range req.Tools {
		tools = append(tools, responsesTool{
			Type:        "function",
			Name:        t.Name,
			Description: t.Description,
			Parameters:  t.Parameters,
		})
	}

	model := req.Model
	if model == "" {
		model = o.model
	}
	temp := req.Temperature
	if temp == 0 {
		temp = o.temperature
	}

	apiReq := responsesRequest{
		Model:        model,
		Instructions: instructions,
		Input:        input,
		Tools:        tools,
		Stream:       true,
	}

	body, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	log.Printf("📡 Calling Codex Responses API (%s)...", model)

	httpReq, err := http.NewRequest("POST", codexResponsesURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := o.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to Codex API: %w", err)
	}
	defer resp.Body.Close()

	// On 401, refresh token and retry
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		log.Println("⚠️  Got 401 from Codex API, refreshing OAuth token...")
		o.codexAuth.ClearCache()
		newToken, err := o.codexAuth.RefreshToken()
		if err != nil {
			return nil, fmt.Errorf("failed to refresh Codex token: %w\nRun 'codex login' to re-authenticate", err)
		}

		httpReq, _ = http.NewRequest("POST", codexResponsesURL, bytes.NewReader(body))
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+newToken)

		resp, err = o.httpClient.Do(httpReq)
		if err != nil {
			return nil, fmt.Errorf("failed to send retry request: %w", err)
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Codex API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	// Parse SSE streaming response
	return o.parseCodexSSEResponse(resp.Body)
}

// SSE event for streaming
type sseEventItem struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	CallID string `json:"call_id,omitempty"`
	Name   string `json:"name,omitempty"`
}

type sseEvent struct {
	Type      string        `json:"type"`
	Delta     string        `json:"delta,omitempty"`
	ItemID    string        `json:"item_id,omitempty"`
	Arguments string        `json:"arguments,omitempty"`
	Item      *sseEventItem `json:"item,omitempty"`
	// For response.completed
	Response *responsesAPIResponse `json:"response,omitempty"`
	// For errors
	Message string `json:"message,omitempty"`
	Code    string `json:"code,omitempty"`
}

// parseCodexSSEResponse reads SSE streaming data from the Codex Responses API
// and assembles it into a complete CompletionResponse
func (o *OpenAIProvider) parseCodexSSEResponse(body io.Reader) (*CompletionResponse, error) {
	result := &CompletionResponse{}

	// Track tool calls by their item_id
	toolCalls := make(map[string]*models.ToolCall) // itemID -> ToolCall
	var textContent strings.Builder

	scanner := bufio.NewScanner(body)
	// Increase scanner buffer for large responses
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		// SSE format: "data: {json}" or empty lines
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}

		var event sseEvent
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			// Skip unparseable events
			log.Printf("⚠️  SSE unparseable: %s", data[:min(len(data), 200)])
			continue
		}

		// Debug: log all event types to discover the correct ones
		if event.Type != "" {
			if strings.Contains(event.Type, "function") || strings.Contains(event.Type, "output_item") || strings.Contains(event.Type, "output_text") {
				// Don't flood logs in production, comment this out after verification
				// log.Printf("📥 SSE event [%s]: %s", event.Type, data)
			} else {
				log.Printf("📥 SSE event: type=%s", event.Type)
			}
		}

		switch event.Type {
		case "response.output_text.delta":
			// Accumulate text deltas
			textContent.WriteString(event.Delta)

		case "response.output_item.added":
			// New function call starting
			if event.Item != nil && event.Item.Type == "function_call" {
				toolCalls[event.Item.ID] = &models.ToolCall{
					ID:   event.Item.CallID,
					Name: event.Item.Name,
				}
			}

		case "response.function_call_arguments.delta":
			// Accumulate function call arguments
			if event.ItemID != "" {
				if tc, ok := toolCalls[event.ItemID]; ok {
					tc.Arguments += event.Delta
				}
			}

		case "response.function_call_arguments.done":
			// Function call complete — set final arguments if provided
			if event.ItemID != "" {
				if tc, ok := toolCalls[event.ItemID]; ok {
					if event.Arguments != "" {
						tc.Arguments = event.Arguments
					}
				}
			}

		case "response.completed":
			// Final event — extract usage if available
			if event.Response != nil && event.Response.Usage != nil {
				result.Usage = TokenUsage{
					PromptTokens:     event.Response.Usage.InputTokens,
					CompletionTokens: event.Response.Usage.OutputTokens,
					TotalTokens:      event.Response.Usage.TotalTokens,
				}
			}

		case "error":
			return nil, fmt.Errorf("Codex streaming error: %s (%s)", event.Message, event.Code)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading SSE stream: %w", err)
	}

	// Assemble result
	result.Content = textContent.String()
	for _, tc := range toolCalls {
		result.ToolCalls = append(result.ToolCalls, *tc)
	}

	log.Printf("✅ Codex API response: %d chars text, %d tool calls, %d tokens",
		len(result.Content), len(result.ToolCalls), result.Usage.TotalTokens)
	return result, nil
}

// ============================================================
// Standard OpenAI Chat Completions API (API key mode)
// Endpoint: https://api.openai.com/v1/chat/completions
// ============================================================

type openAIRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	Tools       []openAITool    `json:"tools,omitempty"`
	Temperature float64         `json:"temperature"`
}

type openAIMessage struct {
	Role       string           `json:"role"`
	Content    string           `json:"content,omitempty"`
	ToolCalls  []openAIToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}

type openAITool struct {
	Type     string             `json:"type"`
	Function openAIToolFunction `json:"function"`
}

type openAIToolFunction struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

type openAIToolCall struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Function openAIToolCallFunction `json:"function"`
}

type openAIToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type openAIResponse struct {
	Choices []openAIChoice `json:"choices"`
	Usage   openAIUsage    `json:"usage"`
	Error   *openAIError   `json:"error,omitempty"`
}

type openAIChoice struct {
	Message openAIMessage `json:"message"`
}

type openAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type openAIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

func (o *OpenAIProvider) completeViaChatCompletions(req CompletionRequest) (*CompletionResponse, error) {
	token, err := o.getAuthToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get auth token: %w", err)
	}

	// Build messages
	messages := make([]openAIMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		msg := openAIMessage{
			Role:       m.Role,
			Content:    m.Content,
			ToolCallID: m.ToolCallID,
		}
		if len(m.ToolCalls) > 0 {
			for _, tc := range m.ToolCalls {
				msg.ToolCalls = append(msg.ToolCalls, openAIToolCall{
					ID:   tc.ID,
					Type: "function",
					Function: openAIToolCallFunction{
						Name:      tc.Name,
						Arguments: tc.Arguments,
					},
				})
			}
		}
		messages = append(messages, msg)
	}

	// Build tools
	var tools []openAITool
	for _, t := range req.Tools {
		tools = append(tools, openAITool{
			Type: "function",
			Function: openAIToolFunction{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Parameters,
			},
		})
	}

	model := req.Model
	if model == "" {
		model = o.model
	}
	temp := req.Temperature
	if temp == 0 {
		temp = o.temperature
	}

	apiReq := openAIRequest{
		Model:       model,
		Messages:    messages,
		Tools:       tools,
		Temperature: temp,
	}

	body, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", openAICompletionsURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := o.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var apiResp openAIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if apiResp.Error != nil {
		return nil, fmt.Errorf("OpenAI API error: %s (%s)", apiResp.Error.Message, apiResp.Error.Type)
	}

	if len(apiResp.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	choice := apiResp.Choices[0]
	result := &CompletionResponse{
		Content: choice.Message.Content,
		Usage: TokenUsage{
			PromptTokens:     apiResp.Usage.PromptTokens,
			CompletionTokens: apiResp.Usage.CompletionTokens,
			TotalTokens:      apiResp.Usage.TotalTokens,
		},
	}

	for _, tc := range choice.Message.ToolCalls {
		result.ToolCalls = append(result.ToolCalls, models.ToolCall{
			ID:        tc.ID,
			Name:      tc.Function.Name,
			Arguments: tc.Function.Arguments,
		})
	}

	return result, nil
}
