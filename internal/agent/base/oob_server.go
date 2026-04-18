package base

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OOBCallback holds a single captured out-of-band HTTP callback.
type OOBCallback struct {
	Token     string
	RemoteIP  string
	Path      string
	Headers   map[string]string
	Timestamp time.Time
}

// OOBServer is an in-process HTTP server that listens for out-of-band callbacks
// from blind injection payloads (Log4Shell JNDI, blind XSS, blind SQLi OOB, SSRF).
type OOBServer struct {
	addr      string   // e.g. ":19876"
	callbacks sync.Map // token → []OOBCallback
	server    *http.Server
}

// NewOOBServer creates an OOBServer that will listen on addr.
func NewOOBServer(addr string) *OOBServer {
	return &OOBServer{addr: addr}
}

// Start starts the HTTP server in a background goroutine.
// It returns an error if the listener cannot be created. The server runs
// until ctx is cancelled or Stop is called.
func (o *OOBServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/cb/", o.handleCallback)

	o.server = &http.Server{
		Addr:    o.addr,
		Handler: mux,
	}

	// Run in background; ignore the normal "server closed" error.
	go func() {
		if err := o.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Best-effort: server already stopped
			_ = err
		}
	}()

	// Shut down the server when the context is done.
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = o.server.Shutdown(shutCtx)
	}()

	return nil
}

// Stop gracefully shuts down the server.
func (o *OOBServer) Stop() error {
	if o.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return o.server.Shutdown(ctx)
}

// GenerateToken returns a unique token optionally labelled with label.
// The label is prefixed to the hex bytes to make debug output readable.
func (o *OOBServer) GenerateToken(label string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	if label != "" {
		// Sanitise label for use inside a URL path segment.
		safe := strings.NewReplacer("/", "-", " ", "-").Replace(label)
		return safe + "-" + tok
	}
	return tok
}

// CallbackURL returns the full URL that a target should call back to for token.
func (o *OOBServer) CallbackURL(token string) string {
	host := o.addr
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	return fmt.Sprintf("http://%s/cb/%s", host, token)
}

// WaitForCallback blocks until a callback is recorded for token, the timeout
// elapses, or ctx is cancelled.  It polls every 500 ms.
func (o *OOBServer) WaitForCallback(ctx context.Context, token string, timeout time.Duration) (*OOBCallback, bool) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, false
		case <-ticker.C:
			cbs := o.GetCallbacks(token)
			if len(cbs) > 0 {
				cb := cbs[0]
				return &cb, true
			}
			if time.Now().After(deadline) {
				return nil, false
			}
		}
	}
}

// GetCallbacks returns all callbacks recorded for token.
func (o *OOBServer) GetCallbacks(token string) []OOBCallback {
	val, ok := o.callbacks.Load(token)
	if !ok {
		return nil
	}
	return val.([]OOBCallback)
}

// handleCallback is the HTTP handler for GET/POST /cb/{token}.
func (o *OOBServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Extract token from path: /cb/{token}
	path := r.URL.Path
	token := strings.TrimPrefix(path, "/cb/")
	token = strings.TrimLeft(token, "/")

	remoteIP := r.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
		remoteIP = remoteIP[:idx]
	}
	remoteIP = strings.Trim(remoteIP, "[]")

	headers := make(map[string]string, len(r.Header))
	for k, vs := range r.Header {
		headers[k] = strings.Join(vs, ", ")
	}

	cb := OOBCallback{
		Token:     token,
		RemoteIP:  remoteIP,
		Path:      path,
		Headers:   headers,
		Timestamp: time.Now(),
	}

	// Append atomically using sync.Map + slice swap.
	for {
		existing, loaded := o.callbacks.Load(token)
		var newSlice []OOBCallback
		if loaded {
			newSlice = append(existing.([]OOBCallback), cb)
		} else {
			newSlice = []OOBCallback{cb}
		}
		if loaded {
			if o.callbacks.CompareAndSwap(token, existing, newSlice) {
				break
			}
		} else {
			if _, loaded2 := o.callbacks.LoadOrStore(token, newSlice); !loaded2 {
				break
			}
		}
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// GlobalOOBServer is the package-level singleton OOB server.
var GlobalOOBServer = NewOOBServer(":19876")
