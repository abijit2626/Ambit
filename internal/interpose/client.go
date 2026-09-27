package interpose

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// Client posts reports to ambitd over loopback.
type Client struct {
	url  string
	http *http.Client

	sent    atomic.Int64
	dropped atomic.Int64
}

// DefaultTimeout bounds a report POST. It is generous relative to a loopback
// round trip and short relative to a developer's patience: the send happens off
// the relay path, but a wedged ambitd must not accumulate goroutines either.
const DefaultTimeout = 2 * time.Second

// NewClient builds a client for an ambitd hook address such as 127.0.0.1:7777.
func NewClient(addr string) *Client {
	return &Client{
		url:  "http://" + addr + Path,
		http: &http.Client{Timeout: DefaultTimeout},
	}
}

// URL reports the endpoint being posted to.
func (c *Client) URL() string { return c.url }

// Send posts a report. An error means the report was lost, which is a reportable
// condition but never a reason to disturb the MCP stream: the caller counts it and
// carries on.
func (c *Client) Send(ctx context.Context, rep *Report) error {
	body, err := json.Marshal(rep)
	if err != nil {
		c.dropped.Add(1)
		return fmt.Errorf("interpose: encode report: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		c.dropped.Add(1)
		return fmt.Errorf("interpose: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		c.dropped.Add(1)
		return fmt.Errorf("interpose: post report: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		c.dropped.Add(1)
		return fmt.Errorf("interpose: ambitd returned %s", resp.Status)
	}
	c.sent.Add(1)
	return nil
}

// Stats reports delivery counters.
func (c *Client) Stats() (sent, dropped int64) {
	return c.sent.Load(), c.dropped.Load()
}
