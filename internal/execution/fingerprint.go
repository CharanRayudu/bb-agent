package execution

import (
	"net/http"
	"sort"
	"strings"
)

// RequestFingerprint binds an approval to the method, URL, body, and the
// headers that change who the request acts as. A different body or
// Authorization value does not reuse this approval.
func RequestFingerprint(method, rawURL string, header http.Header, body []byte) string {
	var b strings.Builder
	b.WriteString(strings.ToUpper(method))
	b.WriteByte('\n')
	b.WriteString(rawURL)
	b.WriteByte('\n')
	keys := []string{"Authorization", "Cookie", "Origin", "Content-Type"}
	sort.Strings(keys)
	for _, key := range keys {
		b.WriteString(key)
		b.WriteByte('=')
		if header != nil {
			b.WriteString(strings.Join(header.Values(key), ","))
		}
		b.WriteByte('\n')
	}
	b.Write(body)
	return Digest(b.String())
}
