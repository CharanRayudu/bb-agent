package execution

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Do sends one HTTP action through the gateway. The socket is dialed to the
// addresses authorized for this attempt. Redirects are not followed here;
// a later request is a new action.
func (g *Gateway) Do(ctx context.Context, action Action, mutate func(*http.Request)) (*http.Response, error) {
	if g == nil {
		return nil, ErrGatewayRequired
	}
	current := action
	current.FollowRedirects = false
	decision, ips, err := g.decide(ctx, current, true)
	if err != nil || !decision.Allowed {
		if err == nil {
			err = denial(decision)
		}
		return nil, err
	}
	ctx = WithEgress(ctx, g.egress)
	if FlowID(ctx) == "" && current.FlowID != "" {
		ctx = WithFlowID(ctx, current.FlowID)
	}
	req, err := http.NewRequestWithContext(ctx, methodOf(current), urlOf(current), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")
	if mutate != nil {
		mutate(req)
	}
	if g.roundTrip != nil {
		return g.roundTrip(req, ips)
	}
	return pinnedHTTP(req, ips)
}

func pinnedHTTP(req *http.Request, ips []net.IP) (*http.Response, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialPinned(ctx, network, addr, ips)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	return client.Do(req)
}

func methodOf(action Action) string {
	if action.Arguments != nil && action.Arguments["method"] != "" {
		return action.Arguments["method"]
	}
	return http.MethodGet
}

func urlOf(action Action) string {
	if action.Arguments != nil && action.Arguments["url"] != "" {
		return action.Arguments["url"]
	}
	scheme := action.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := action.Host
	if action.Port != 0 {
		host = host + ":" + strconv.Itoa(action.Port)
	}
	path := action.Path
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path
}

func isRedirect(code int) bool {
	return code == http.StatusMovedPermanently ||
		code == http.StatusFound ||
		code == http.StatusSeeOther ||
		code == http.StatusTemporaryRedirect ||
		code == http.StatusPermanentRedirect
}

// FollowRedirect sends the authorized request and authorizes each subsequent hop.
func (g *Gateway) FollowRedirect(ctx context.Context, action Action, mutate func(*http.Request)) (*http.Response, error) {
	current := action
	var last *http.Response
	for hop := 0; hop < 4; hop++ {
		resp, err := g.Do(ctx, current, mutate)
		if err != nil {
			if last != nil && last.Body != nil {
				last.Body.Close()
			}
			return nil, err
		}
		last = resp
		if !action.FollowRedirects || !isRedirect(resp.StatusCode) {
			return resp, nil
		}
		loc, err := resp.Location()
		if err != nil {
			return resp, nil
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		next, err := HTTPAction(current.FlowID, current.SkillID, methodOf(current), loc.String())
		if err != nil {
			return nil, err
		}
		next = next.WithRisk(current.Risk)
		next.ActorID = current.ActorID
		next.ID = current.ID + ":hop:" + strconv.Itoa(hop+1)
		next.FollowRedirects = true
		current = next
		action.FollowRedirects = true
	}
	return last, nil
}
