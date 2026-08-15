// Package adguard is a thin client for the AdGuard Home HTTP API. It covers the
// read paths and, as of M1, client create/update; rewrite writes and client
// delete land in later milestones (design doc §7.3).
package adguard

import (
	"bytes"
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

// ClientCreate is the payload for creating a persistent client. UseGlobalSettings
// defaults to true so a new client inherits global filtering rather than silently
// starting with all protection off; both flags come from the sink's `defaults`.
type ClientCreate struct {
	Name              string
	IDs               []string
	Tags              []string
	UseGlobalSettings bool
	FilteringEnabled  bool
}

// AddClient creates a persistent client.
func (c *Client) AddClient(ctx context.Context, cl ClientCreate) error {
	body := struct {
		Name              string   `json:"name"`
		IDs               []string `json:"ids"`
		Tags              []string `json:"tags,omitempty"`
		UseGlobalSettings bool     `json:"use_global_settings"`
		FilteringEnabled  bool     `json:"filtering_enabled"`
	}{
		Name:              cl.Name,
		IDs:               cl.IDs,
		Tags:              cl.Tags,
		UseGlobalSettings: cl.UseGlobalSettings,
		FilteringEnabled:  cl.FilteringEnabled,
	}
	return c.postJSON(ctx, "/control/clients/add", body, nil)
}

// UpdateClient replaces a live client, overlaying the managed fields and copying
// every other field through untouched. Client update is a full replacement
// (§7.3), so the overlay starts from the live object's Raw to avoid clobbering
// fields the tool does not manage. ids are always overlaid; tags are overlaid
// only when the sink manages them (i.e. enrichment is configured).
func (c *Client) UpdateClient(ctx context.Context, live PersistentClient, ids, tags []string, manageTags bool) error {
	data := make(map[string]json.RawMessage, len(live.Raw)+1)
	for k, v := range live.Raw {
		data[k] = v
	}
	if err := setField(data, "ids", ids); err != nil {
		return err
	}
	if manageTags {
		// Marshal an empty tag set as [] (not null) so tags are actively cleared.
		if tags == nil {
			tags = []string{}
		}
		if err := setField(data, "tags", tags); err != nil {
			return err
		}
	}
	if _, ok := data["name"]; !ok {
		if err := setField(data, "name", live.Name); err != nil {
			return err
		}
	}
	body := struct {
		Name string                     `json:"name"`
		Data map[string]json.RawMessage `json:"data"`
	}{Name: live.Name, Data: data}
	return c.postJSON(ctx, "/control/clients/update", body, nil)
}

// DeleteClient removes a persistent client by name (pruning, §7.6).
func (c *Client) DeleteClient(ctx context.Context, name string) error {
	body := struct {
		Name string `json:"name"`
	}{Name: name}
	return c.postJSON(ctx, "/control/clients/delete", body, nil)
}

// setField marshals v and stores it in data under key.
func setField(data map[string]json.RawMessage, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data[key] = b
	return nil
}

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

// postJSON sends body as JSON and, when out is non-nil and a JSON body comes
// back, decodes it. AdGuard's client mutations typically return an empty 200.
func (c *Client) postJSON(ctx context.Context, path string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("adguard: encoding %s body: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("adguard: POST %s: %w", path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("adguard: reading %s: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("adguard: POST %s: %s: %s", path, resp.Status, snippet(respBody))
	}
	if out != nil && len(bytes.TrimSpace(respBody)) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("adguard: decoding %s response: %w", path, err)
		}
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
