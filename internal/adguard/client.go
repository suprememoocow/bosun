// Package adguard is a thin client for the AdGuard Home HTTP API. In M0 only
// the read paths (list clients, list rewrites) are used; the write paths are
// stubs wired up in later milestones (design doc §7.3).
package adguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrNotImplemented is returned by the write paths until their milestone lands.
var ErrNotImplemented = errors.New("adguard: operation not implemented yet")

// Client talks to a single AdGuard Home instance. Authentication is HTTP Basic
// on every request, which keeps the client stateless — no login session to
// track, consistent with the tool's no-state principle.
type Client struct {
	baseURL  string
	username string
	password string
	http     *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the underlying *http.Client (used in tests).
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// New builds a Client for the given base address (e.g. http://host:3000).
func New(address, username, password string, opts ...Option) (*Client, error) {
	if _, err := url.Parse(address); err != nil {
		return nil, fmt.Errorf("adguard: invalid address %q: %w", address, err)
	}
	c := &Client{
		baseURL:  strings.TrimRight(address, "/"),
		username: username,
		password: password,
		http:     &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// ListClients returns the persistent clients (auto-clients are ignored).
func (c *Client) ListClients(ctx context.Context) ([]PersistentClient, error) {
	var resp clientsResponse
	if err := c.getJSON(ctx, "/control/clients", &resp); err != nil {
		return nil, err
	}
	return resp.Clients, nil
}

// ListRewrites returns all DNS rewrite entries.
func (c *Client) ListRewrites(ctx context.Context) ([]Rewrite, error) {
	var rewrites []Rewrite
	if err := c.getJSON(ctx, "/control/rewrite/list", &rewrites); err != nil {
		return nil, err
	}
	return rewrites, nil
}

// AddClient is implemented in M1.
func (c *Client) AddClient(ctx context.Context, client PersistentClient) error {
	return ErrNotImplemented
}

// UpdateClient is implemented in M2.
func (c *Client) UpdateClient(ctx context.Context, client PersistentClient) error {
	return ErrNotImplemented
}

// DeleteClient is implemented in M2.
func (c *Client) DeleteClient(ctx context.Context, name string) error { return ErrNotImplemented }

// AddRewrite is implemented in M3.
func (c *Client) AddRewrite(ctx context.Context, r Rewrite) error { return ErrNotImplemented }

// DeleteRewrite is implemented in M3.
func (c *Client) DeleteRewrite(ctx context.Context, r Rewrite) error { return ErrNotImplemented }

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("adguard: GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("adguard: reading %s: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("adguard: GET %s: %s: %s", path, resp.Status, snippet(body))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("adguard: decoding %s: %w", path, err)
	}
	return nil
}

func snippet(b []byte) string {
	const max = 200
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
