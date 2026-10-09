package execution

import (
	"context"
	"io"
	"net/http"
	"strconv"
)

// Trip performs one HTTP round trip and must not follow redirects.
type Trip func(*http.Request) (*http.Response, error)

// Do sends an HTTP action through the gateway. Redirect hops are authorized
// again before the next request is sent.
func (g *Gateway) Do(ctx context.Context, action Action, trip Trip) (*http.Response, error) {
	if g == nil {
		return nil, ErrGatewayRequired
	}
	if trip == nil {
		return nil, ErrDenied
	}
	current := action
	var last *http.Response
	for hop := 0; hop < 4; hop++ {
		if _, err := g.Authorize(ctx, current); err != nil {
			if last != nil && last.Body != nil {
				last.Body.Close()
			}
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, methodOf(current), urlOf(current), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")
		resp, err := trip(req)
		if err != nil {
			return nil, err
		}
		last = resp
		if !current.FollowRedirects || !isRedirect(resp.StatusCode) {
			return resp, nil
		}
		loc, err := resp.Location()
		if err != nil {
			return resp, nil
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		next, err := HTTPAction(current.FlowID, current.SkillID, req.Method, loc.String())
		if err != nil {
			return nil, err
		}
		next.FollowRedirects = true
		next.Risk = current.Risk
		next.Phase = current.Phase
		next.ActorID = current.ActorID
		next.ID = current.ID + ":hop:" + strconv.Itoa(hop+1)
		current = next
	}
	return last, nil
}

func methodOf(action Action) string {
	if action.Arguments != nil && action.Arguments["method"] != "" {
		return action.Arguments["method"]
	}
	return http.MethodGet
}

func urlOf(action Action) string {
	if action.Arguments != nil && action.Arguments["url"] != "" && action.Port == 0 {
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
