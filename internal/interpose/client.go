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

type Client struct {
	url  string
	http *http.Client

	sent    atomic.Int64
	dropped atomic.Int64
}

const DefaultTimeout = 2 * time.Second

func NewClient(addr string) *Client {
	return &Client{
		url:  "http://" + addr + Path,
		http: &http.Client{Timeout: DefaultTimeout},
	}
}

func (c *Client) URL() string { return c.url }

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

func (c *Client) Stats() (sent, dropped int64) {
	return c.sent.Load(), c.dropped.Load()
}
