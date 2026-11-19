package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// WebhookPayload is posted to the configured webhook URL. "text" is a ready-made
// summary (renders in Slack/Discord-style receivers); the structured fields are
// for automation.
type WebhookPayload struct {
	Text     string         `json:"text"`
	Event    string         `json:"event"`
	ScanID   string         `json:"scan_id"`
	Asset    string         `json:"asset"`
	Status   string         `json:"status"`
	Findings int            `json:"findings"`
	Severity map[string]int `json:"severity"`
}

// sendWebhook POSTs the payload as JSON. Any 2xx is success.
func sendWebhook(url string, payload WebhookPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("notify: webhook post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notify: webhook status %d", resp.StatusCode)
	}
	return nil
}
