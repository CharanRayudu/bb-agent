package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// EPSSScore holds the EPSS (Exploit Prediction Scoring System) data for a CVE.
type EPSSScore struct {
	CVE        string  `json:"cve"`
	EPSS       float64 `json:"epss"`       // 0.0–1.0 probability of exploitation in 30 days
	Percentile float64 `json:"percentile"` // 0.0–1.0 percentile among all CVEs
	Date       string  `json:"date"`
}

// KEVEntry is a CISA Known Exploited Vulnerability catalog entry.
type KEVEntry struct {
	CVEID                string `json:"cveID"`
	VendorProject        string `json:"vendorProject"`
	Product              string `json:"product"`
	VulnerabilityName    string `json:"vulnerabilityName"`
	DateAdded            string `json:"dateAdded"`
	ShortDescription     string `json:"shortDescription"`
	RequiredAction       string `json:"requiredAction"`
	DueDate              string `json:"dueDate"`
	Notes                string `json:"notes"`
}

// EnrichedCVE combines CVSS, EPSS, and KEV data for a CVE.
type EnrichedCVE struct {
	CVE          string     `json:"cve"`
	EPSS         *EPSSScore `json:"epss,omitempty"`
	InKEV        bool       `json:"in_kev"`
	KEVEntry     *KEVEntry  `json:"kev_entry,omitempty"`
	RiskScore    float64    `json:"risk_score"` // 0–100
	RiskLabel    string     `json:"risk_label"` // critical / high / medium / low
}

// epssCache is an in-memory cache for EPSS scores to avoid repeated API calls.
var epssCache sync.Map // map[string]*EPSSScore

// kevCache is populated lazily on first KEV fetch.
var (
	kevCache   map[string]*KEVEntry
	kevCacheMu sync.RWMutex
	kevFetched bool
)

const (
	epssAPIBase = "https://api.first.org/data/v1/epss"
	kevCatalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

// FetchEPSS fetches EPSS scores for a list of CVE IDs.
// Uses an in-memory cache to avoid duplicate API calls.
func FetchEPSS(ctx context.Context, client *http.Client, cveIDs []string) map[string]*EPSSScore {
	if len(cveIDs) == 0 {
		return nil
	}

	// Check cache first
	results := map[string]*EPSSScore{}
	var missing []string
	for _, id := range cveIDs {
		if v, ok := epssCache.Load(id); ok {
			results[id] = v.(*EPSSScore)
		} else {
			missing = append(missing, id)
		}
	}

	if len(missing) == 0 {
		return results
	}

	// Batch fetch up to 100 CVEs at a time
	for i := 0; i < len(missing); i += 100 {
		end := i + 100
		if end > len(missing) {
			end = len(missing)
		}
		batch := missing[i:end]
		fetched := fetchEPSSBatch(ctx, client, batch)
		for id, score := range fetched {
			results[id] = score
			epssCache.Store(id, score)
		}
	}
	return results
}

func fetchEPSSBatch(ctx context.Context, client *http.Client, cveIDs []string) map[string]*EPSSScore {
	url := fmt.Sprintf("%s?cve=%s", epssAPIBase, strings.Join(cveIDs, ","))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return nil
	}

	var out struct {
		Status string `json:"status"`
		Data   []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
			Date       string `json:"date"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil
	}

	results := map[string]*EPSSScore{}
	for _, d := range out.Data {
		var epss, pct float64
		fmt.Sscanf(d.EPSS, "%f", &epss)
		fmt.Sscanf(d.Percentile, "%f", &pct)
		results[d.CVE] = &EPSSScore{
			CVE:        d.CVE,
			EPSS:       epss,
			Percentile: pct,
			Date:       d.Date,
		}
	}
	return results
}

// FetchKEV fetches and caches the CISA Known Exploited Vulnerabilities catalog.
func FetchKEV(ctx context.Context, client *http.Client) map[string]*KEVEntry {
	kevCacheMu.RLock()
	if kevFetched {
		defer kevCacheMu.RUnlock()
		return kevCache
	}
	kevCacheMu.RUnlock()

	kevCacheMu.Lock()
	defer kevCacheMu.Unlock()
	if kevFetched {
		return kevCache
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kevCatalogURL, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 20*1024*1024))
	if err != nil {
		return nil
	}

	var catalog struct {
		Vulnerabilities []KEVEntry `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil
	}

	kevCache = map[string]*KEVEntry{}
	for i := range catalog.Vulnerabilities {
		entry := &catalog.Vulnerabilities[i]
		kevCache[entry.CVEID] = entry
	}
	kevFetched = true
	return kevCache
}

// EnrichCVEs looks up EPSS and KEV data for a list of CVE IDs and computes
// a composite risk score.
func EnrichCVEs(ctx context.Context, cveIDs []string, cvssScores map[string]float64) []EnrichedCVE {
	if len(cveIDs) == 0 {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Fetch in parallel
	epssResultsCh := make(chan map[string]*EPSSScore, 1)
	kevResultsCh := make(chan map[string]*KEVEntry, 1)

	go func() { epssResultsCh <- FetchEPSS(ctx, client, cveIDs) }()
	go func() { kevResultsCh <- FetchKEV(ctx, client) }()

	epssResults := <-epssResultsCh
	kevResults := <-kevResultsCh

	var enriched []EnrichedCVE
	for _, cve := range cveIDs {
		e := EnrichedCVE{CVE: cve}

		if epss, ok := epssResults[cve]; ok {
			e.EPSS = epss
		}
		if kev, ok := kevResults[cve]; ok {
			e.InKEV = true
			e.KEVEntry = kev
		}

		cvss := cvssScores[cve]
		e.RiskScore = CompositeRiskScore(cvss, e.EPSS, e.InKEV, 0, "")
		e.RiskLabel = RiskLabel(e.RiskScore)

		enriched = append(enriched, e)
	}
	return enriched
}
