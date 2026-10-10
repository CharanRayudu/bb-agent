package execution

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/policy"
)

func TestConcurrentFirewallUpdatesAtomicNoPermissiveWindow(t *testing.T) {
	fc := NewFirewallController()

	fc.SetCommandRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	})

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	// Launch 10 concurrent flow rule updates
	for i := 0; i < 10; i++ {
		wg.Add(1)
		flowID := fmt.Sprintf("flow-%d", i)
		ipStr := fmt.Sprintf("10.0.0.%d", i+1)
		go func(fid, ip string, port int) {
			defer wg.Done()
			auth := policy.Authorization{
				FlowID:           fid,
				AllowedProtocols: []string{"tcp"},
				Targets: []policy.Target{
					{Host: ip, Port: port},
				},
			}
			rules := BuildRulesFromAuth(auth)
			if err := fc.ApplyFlowRules(context.Background(), fid, rules); err != nil {
				errCh <- fmt.Errorf("ApplyFlowRules failed for %s: %w", fid, err)
				return
			}
			time.Sleep(1 * time.Millisecond)
			if !fc.IsAllowed(fid, net.ParseIP(ip), port, "tcp") {
				errCh <- fmt.Errorf("IsAllowed returned false for authorized target %s:%d on %s", ip, port, fid)
			}
			if fc.IsAllowed(fid, net.ParseIP("8.8.8.8"), 80, "tcp") {
				errCh <- fmt.Errorf("IsAllowed returned true for unpermitted target 8.8.8.8:80 on %s", fid)
			}
		}(flowID, ipStr, 8080+i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Error(err)
	}
}
