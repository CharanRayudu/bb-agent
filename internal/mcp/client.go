// Package mcp implements a Model Context Protocol (MCP) client that
// discovers and executes tools from MCP-compatible servers, dynamically
// registering them into Mirage's tool registry.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// ToolSchema represents an MCP tool's parameter schema.
type ToolSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Required   []string               `json:"required,omitempty"`
}

// MCPTool represents a tool discovered from an MCP server.
type MCPTool struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	InputSchema ToolSchema `json:"inputSchema"`
	ServerID    string     `json:"server_id"`
}

// MCPServer represents a configured MCP server endpoint.
type MCPServer struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`    // HTTP transport URL
	Type    string `json:"type"`   // "http", "stdio", "sse"
	Status  string `json:"status"` // "connected", "error", "disconnected"
	Tools   []MCPTool `json:"tools,omitempty"`
}

// Client manages connections to MCP servers and provides tool discovery/execution.
type Client struct {
	servers    map[string]*MCPServer
	tools      map[string]*MCPTool
	httpClient *http.Client
	mu         sync.RWMutex
}

// NewClient creates a new MCP client.
func NewClient() *Client {
	return &Client{
		servers: make(map[string]*MCPServer),
		tools:   make(map[string]*MCPTool),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// RegisterServer adds an MCP server configuration.
func (c *Client) RegisterServer(server MCPServer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	server.Status = "disconnected"
	c.servers[server.ID] = &server
	log.Printf("[mcp] Registered server: %s (%s)", server.Name, server.URL)
}

// DiscoverTools connects to all registered servers and discovers available tools.
func (c *Client) DiscoverTools(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, server := range c.servers {
		tools, err := c.discoverServerTools(ctx, server)
		if err != nil {
			log.Printf("[mcp] Failed to discover tools from %s: %v", server.Name, err)
			server.Status = "error"
			continue
		}
		server.Status = "connected"
		server.Tools = tools
		for i := range tools {
			tools[i].ServerID = server.ID
			c.tools[tools[i].Name] = &tools[i]
		}
		log.Printf("[mcp] Discovered %d tools from %s", len(tools), server.Name)
	}
	return nil
}

// GetTools returns all discovered tools.
func (c *Client) GetTools() []MCPTool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]MCPTool, 0, len(c.tools))
	for _, t := range c.tools {
		result = append(result, *t)
	}
	return result
}

// GetTool returns a specific tool by name.
func (c *Client) GetTool(name string) (*MCPTool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	t, ok := c.tools[name]
	return t, ok
}

// ExecuteTool calls a tool on its MCP server and returns the result.
func (c *Client) ExecuteTool(ctx context.Context, toolName string, args json.RawMessage) (string, error) {
	c.mu.RLock()
	tool, ok := c.tools[toolName]
	if !ok {
		c.mu.RUnlock()
		return "", fmt.Errorf("MCP tool %s not found", toolName)
	}
	server, ok := c.servers[tool.ServerID]
	if !ok {
		c.mu.RUnlock()
		return "", fmt.Errorf("MCP server %s not found for tool %s", tool.ServerID, toolName)
	}
	c.mu.RUnlock()

	return c.callTool(ctx, server, toolName, args)
}

// GetServers returns all registered servers with their status.
func (c *Client) GetServers() []MCPServer {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]MCPServer, 0, len(c.servers))
	for _, s := range c.servers {
		result = append(result, *s)
	}
	return result
}

// --- JSON-RPC transport for MCP protocol ---

type jsonRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolsListResult struct {
	Tools []MCPTool `json:"tools"`
}

type toolCallResult struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text,omitempty"`
	} `json:"content"`
	IsError bool `json:"isError,omitempty"`
}

// discoverServerTools calls tools/list on an MCP server.
func (c *Client) discoverServerTools(ctx context.Context, server *MCPServer) ([]MCPTool, error) {
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", server.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("invalid response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	var result toolsListResult
	if err := json.Unmarshal(rpcResp.Result, &result); err != nil {
		return nil, fmt.Errorf("invalid tools list: %w", err)
	}

	return result.Tools, nil
}

// callTool executes a tool via JSON-RPC on an MCP server.
func (c *Client) callTool(ctx context.Context, server *MCPServer, toolName string, args json.RawMessage) (string, error) {
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      toolName,
			"arguments": json.RawMessage(args),
		},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", server.URL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("tool call failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return "", fmt.Errorf("invalid response: %w", err)
	}

	if rpcResp.Error != nil {
		return "", fmt.Errorf("tool error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	var result toolCallResult
	if err := json.Unmarshal(rpcResp.Result, &result); err != nil {
		return string(rpcResp.Result), nil
	}

	if result.IsError {
		var texts []string
		for _, c := range result.Content {
			if c.Text != "" {
				texts = append(texts, c.Text)
			}
		}
		return "", fmt.Errorf("MCP tool error: %s", joinStrings(texts, "; "))
	}

	var output []string
	for _, c := range result.Content {
		if c.Text != "" {
			output = append(output, c.Text)
		}
	}
	return joinStrings(output, "\n"), nil
}

func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	result := ss[0]
	for _, s := range ss[1:] {
		result += sep + s
	}
	return result
}
