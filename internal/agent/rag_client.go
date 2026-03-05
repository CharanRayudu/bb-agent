package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// RAGClient handles communication with the external Python RAG Knowledge Base.
type RAGClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewRAGClient creates a new client to talk to the local Knowledge Service.
func NewRAGClient(baseURL string) *RAGClient {
	if baseURL == "" {
		baseURL = "http://127.0.0.1:8081"
	}
	return &RAGClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// KnowledgeQuery represents the JSON payload to the RAG service.
type KnowledgeQuery struct {
	Query string `json:"query"`
	TopK  int    `json:"top_k"`
}

// RAGResponse represents the result from the Python FastAPI service.
type RAGResponse struct {
	Success      bool          `json:"success"`
	Query        string        `json:"query"`
	TotalResults int           `json:"total_results"`
	Results      []RAGDocument `json:"results"`
	Error        string        `json:"error,omitempty"`
}

// RAGDocument represents a single returned chunk from FAISS.
type RAGDocument struct {
	Content  string                 `json:"content"`
	Metadata map[string]interface{} `json:"metadata"`
	Score    float64                `json:"score"`
}

// RetrieveKnowledge queries the FAISS vector DB for relevant payloads/techniques.
func (c *RAGClient) RetrieveKnowledge(ctx context.Context, query string, topK int) (string, error) {
	if topK <= 0 {
		topK = 5
	}

	payload := KnowledgeQuery{
		Query: query,
		TopK:  topK,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/retrieve_knowledge", c.BaseURL), bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		log.Printf("[RAGClient] Failed to reach RAG server at %s. Ensure run-rag.bat is running: %v", c.BaseURL, err)
		return "", fmt.Errorf("RAG service unavailable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("RAG service returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var rags RAGResponse
	if err := json.NewDecoder(resp.Body).Decode(&rags); err != nil {
		return "", err
	}

	if !rags.Success {
		return "", fmt.Errorf("RAG service error: %s", rags.Error)
	}

	if rags.TotalResults == 0 {
		return "No specific knowledge base context found for this query.", nil
	}

	// Format the results into a single context string to inject into prompts
	var contextBuilder strings.Builder
	contextBuilder.WriteString("=== RELEVANT KNOWLEDGE BASE CONTEXT ===\n")
	for i, doc := range rags.Results {
		contextBuilder.WriteString(fmt.Sprintf("-- Document %d (Relevance: %.2f) --\n", i+1, doc.Score))
		if source, ok := doc.Metadata["source"]; ok {
			contextBuilder.WriteString(fmt.Sprintf("Source: %s\n", source))
		}
		contextBuilder.WriteString(doc.Content)
		contextBuilder.WriteString("\n\n")
	}

	return contextBuilder.String(), nil
}
