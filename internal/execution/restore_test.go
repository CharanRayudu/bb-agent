package execution

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/policy"
)

func init() {
	sql.Register("mirage_restore", &restoreDriver{})
}

type restoreFixture struct {
	mu       sync.Mutex
	document string
	approval []driver.Value
	fail     bool
}

var restoreRowsFixture restoreFixture

type restoreDriver struct{}

func (restoreDriver) Open(name string) (driver.Conn, error) {
	return &restoreConn{fail: name == "fail"}, nil
}

type restoreConn struct{ fail bool }

func (c *restoreConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is unused")
}
func (c *restoreConn) Close() error { return nil }
func (c *restoreConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are unused")
}

func (c *restoreConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	restoreRowsFixture.mu.Lock()
	defer restoreRowsFixture.mu.Unlock()
	if c.fail || restoreRowsFixture.fail {
		return nil, errors.New("postgres unavailable")
	}
	if strings.Contains(query, "engagement_authorizations") {
		return &restoreRows{
			cols: []string{"document"},
			data: [][]driver.Value{{restoreRowsFixture.document}},
		}, nil
	}
	if strings.Contains(query, "approval_requests") {
		return &restoreRows{
			cols: []string{"id", "action_key", "flow_id", "phase", "status", "actor", "reason", "expires_at", "created_at", "method", "target", "digest", "risk", "capability"},
			data: [][]driver.Value{restoreRowsFixture.approval},
		}, nil
	}
	return nil, errors.New("unexpected query")
}

type restoreRows struct {
	cols []string
	data [][]driver.Value
	i    int
}

func (r *restoreRows) Columns() []string { return r.cols }
func (r *restoreRows) Close() error      { return nil }
func (r *restoreRows) Next(dest []driver.Value) error {
	if r.i >= len(r.data) {
		return io.EOF
	}
	row := r.data[r.i]
	r.i++
	for i := range dest {
		if i < len(row) {
			dest[i] = row[i]
		}
	}
	return nil
}

func TestPostgreSQLStateRestoresAuthorizationAndApproval(t *testing.T) {
	auth := testAuth(policy.AutonomyL1, "http://example.com")
	auth.EngagementID = "flow-1"
	document, err := json.Marshal(auth)
	if err != nil {
		t.Fatal(err)
	}
	action := httpAct(t, "http://example.com/health")
	restoreRowsFixture.mu.Lock()
	restoreRowsFixture.fail = false
	restoreRowsFixture.document = string(document)
	restoreRowsFixture.approval = []driver.Value{
		"appr-restored", action.IdempotencyKey, "flow-1", "recon", "approved", "operator", "restored",
		nil, time.Now().Add(-time.Minute), http.MethodGet, "http://example.com/health", action.Digest, "passive", "web.headers.audit",
	}
	restoreRowsFixture.mu.Unlock()

	db, err := sql.Open("mirage_restore", "ok")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	book := policy.NewBook()
	mem := NewMemoryStore()
	if err := LoadState(context.Background(), db, book, mem); err != nil {
		t.Fatal(err)
	}
	gw := NewGateway(book, mem, &scriptResolver{seq: []net.IP{net.ParseIP("93.184.216.34")}})
	calls := 0
	out, err := gw.Execute(context.Background(), action, func(context.Context, Action) (string, error) {
		calls++
		return "restored", nil
	})
	if err != nil || out.Output != "restored" || calls != 1 {
		t.Fatalf("restored approval did not authorize the same request, out=%q calls=%d err=%v", out.Output, calls, err)
	}
}

func TestPostgreSQLStateRestoreFailsClosed(t *testing.T) {
	restoreRowsFixture.mu.Lock()
	restoreRowsFixture.fail = true
	restoreRowsFixture.mu.Unlock()
	defer func() {
		restoreRowsFixture.mu.Lock()
		restoreRowsFixture.fail = false
		restoreRowsFixture.mu.Unlock()
	}()
	db, err := sql.Open("mirage_restore", "fail")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = LoadState(context.Background(), db, policy.NewBook(), NewMemoryStore())
	if err == nil || !strings.Contains(err.Error(), "postgres unavailable") {
		t.Fatalf("restore err=%v", err)
	}
}

func TestRestoredBudgetStaysExhausted(t *testing.T) {
	auth := testAuth(policy.AutonomyL3, "http://example.com")
	auth.MaxRequests = 1
	auth.RequestsUsed = 1
	document, err := json.Marshal(auth)
	if err != nil {
		t.Fatal(err)
	}
	restoreRowsFixture.mu.Lock()
	restoreRowsFixture.fail = false
	restoreRowsFixture.document = string(document)
	restoreRowsFixture.approval = []driver.Value{
		"appr-none", "unused", "other-flow", "recon", "pending", "", "", nil, time.Now(), "", "", "", "", "",
	}
	restoreRowsFixture.mu.Unlock()
	db, err := sql.Open("mirage_restore", "ok")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	book := policy.NewBook()
	if err := LoadState(context.Background(), db, book, NewMemoryStore()); err != nil {
		t.Fatal(err)
	}
	gw := NewGateway(book, NewMemoryStore(), &scriptResolver{seq: []net.IP{net.ParseIP("93.184.216.34")}})
	calls := 0
	_, err = gw.Execute(context.Background(), httpAct(t, "http://example.com/"), func(context.Context, Action) (string, error) {
		calls++
		return "ran", nil
	})
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatalf("restored budget was reset, calls=%d err=%v", calls, err)
	}
	if gw.Store().Decisions()[len(gw.Store().Decisions())-1].Code != policy.CodeBudgetExhausted {
		t.Fatalf("code=%s", gw.Store().Decisions()[len(gw.Store().Decisions())-1].Code)
	}
}
