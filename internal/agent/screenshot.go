package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
)

// ScreenshotRecord holds a single captured screenshot.
type ScreenshotRecord struct {
	ID         string    `json:"id"`
	FlowID     string    `json:"flow_id"`
	FindingID  string    `json:"finding_id,omitempty"`
	URL        string    `json:"url"`
	Title      string    `json:"title"`
	Data       []byte    `json:"-"` // PNG bytes, omitted from JSON listings
	CapturedAt time.Time `json:"captured_at"`
}

// ScreenshotStore is an in-memory store for screenshot records.
type ScreenshotStore struct {
	records []*ScreenshotRecord
	mu      sync.RWMutex
}

// GlobalScreenshots is the process-wide screenshot store.
var GlobalScreenshots = &ScreenshotStore{}

// Add appends a record to the store.
func (s *ScreenshotStore) Add(rec *ScreenshotRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rec)
}

// GetByFlow returns all records for the given flow ID.
func (s *ScreenshotStore) GetByFlow(flowID string) []*ScreenshotRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*ScreenshotRecord
	for _, r := range s.records {
		if r.FlowID == flowID {
			out = append(out, r)
		}
	}
	return out
}

// GetByID looks up a record by its ID.
func (s *ScreenshotStore) GetByID(id string) (*ScreenshotRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.records {
		if r.ID == id {
			return r, true
		}
	}
	return nil, false
}

// CaptureScreenshot navigates to targetURL and returns a PNG screenshot.
// It uses chromedp with a 15-second timeout and Docker-compatible flags.
func CaptureScreenshot(ctx context.Context, targetURL string) ([]byte, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("headless", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	taskCtx, taskCancel := context.WithTimeout(allocCtx, 15*time.Second)
	defer taskCancel()

	chromedpCtx, chromedpCancel := chromedp.NewContext(taskCtx)
	defer chromedpCancel()

	var buf []byte
	err := chromedp.Run(chromedpCtx,
		chromedp.Navigate(targetURL),
		chromedp.CaptureScreenshot(&buf),
	)
	if err != nil {
		return nil, fmt.Errorf("chromedp screenshot failed: %w", err)
	}
	return buf, nil
}

// CaptureAndStore takes a screenshot of the URL and stores it with the given IDs.
func CaptureAndStore(ctx context.Context, flowID, findingID, targetURL, title string) (*ScreenshotRecord, error) {
	data, err := CaptureScreenshot(ctx, targetURL)
	if err != nil {
		return nil, err
	}

	rec := &ScreenshotRecord{
		ID:         uuid.New().String(),
		FlowID:     flowID,
		FindingID:  findingID,
		URL:        targetURL,
		Title:      title,
		Data:       data,
		CapturedAt: time.Now(),
	}
	GlobalScreenshots.Add(rec)
	return rec, nil
}
