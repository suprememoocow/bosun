// Package omada is a client for the local Omada SDN controller API (not the
// cloud OpenAPI). Login yields a CSRF token that must accompany subsequent
// requests, and the controller id is part of every path — both are
// version-sensitive, so the version-specific bits live behind the controllerAPI
// interface and a v5→v6 shim is additive (§6.1).
package omada

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

// Client is an authenticated controller session.
type Client struct {
	http    *http.Client
	base    string
	cid     string // omadacId, part of the request path
	token   string // CSRF token from login
	version string
}

// Dial connects, discovers the controller id and version, and logs in.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{}
	if cfg.InsecureSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	c := &Client{
		http: &http.Client{Jar: jar, Transport: tr, Timeout: 30 * time.Second},
		base: strings.TrimRight(cfg.Address, "/"),
	}

	var info infoResponse
	if err := c.do(ctx, http.MethodGet, "/api/info", nil, &info); err != nil {
		return nil, fmt.Errorf("controller info: %w", err)
	}
	if info.ErrorCode != 0 {
		return nil, fmt.Errorf("controller info: %s", info.Msg)
	}
	c.cid = info.Result.OmadacID
	c.version = info.Result.ControllerVer

	login, _ := json.Marshal(map[string]string{"username": cfg.Username, "password": cfg.Password})
	var lr loginResponse
	if err := c.do(ctx, http.MethodPost, "/"+c.cid+"/api/v2/login", bytes.NewReader(login), &lr); err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}
	if lr.ErrorCode != 0 {
		return nil, fmt.Errorf("login failed: %s", lr.Msg)
	}
	c.token = lr.Result.Token
	return c, nil
}

// SiteID resolves a site name to its id.
func (c *Client) SiteID(ctx context.Context, name string) (string, error) {
	var sr sitesResponse
	path := fmt.Sprintf("/%s/api/v2/sites?currentPage=1&currentPageSize=1000", c.cid)
	if err := c.do(ctx, http.MethodGet, path, nil, &sr); err != nil {
		return "", fmt.Errorf("listing sites: %w", err)
	}
	if sr.ErrorCode != 0 {
		return "", fmt.Errorf("listing sites: %s", sr.Msg)
	}
	for _, s := range sr.Result.Data {
		if s.Name == name {
			return s.ID, nil
		}
	}
	return "", fmt.Errorf("site %q not found", name)
}

// Reservations returns all DHCP reservations for a site, following pagination.
// It fails if any page fails, so a partial result never reaches the caller —
// the completeness contract begins here (§4.3).
func (c *Client) Reservations(ctx context.Context, siteID string) ([]reservation, error) {
	const pageSize = 100
	var all []reservation
	for page := 1; ; page++ {
		var rr reservationsResponse
		path := fmt.Sprintf("/%s/api/v2/sites/%s/setting/service/dhcp?currentPage=%d&currentPageSize=%d",
			c.cid, siteID, page, pageSize)
		if err := c.do(ctx, http.MethodGet, path, nil, &rr); err != nil {
			return nil, fmt.Errorf("fetching reservations page %d: %w", page, err)
		}
		if rr.ErrorCode != 0 {
			return nil, fmt.Errorf("fetching reservations: %s", rr.Msg)
		}
		all = append(all, rr.Result.Data...)
		if len(rr.Result.Data) == 0 || len(all) >= rr.Result.TotalRows {
			break
		}
	}
	return all, nil
}

// do performs a request, attaching the CSRF token once logged in, and decodes
// the JSON response.
func (c *Client) do(ctx context.Context, method, path string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Csrf-Token", c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	return json.Unmarshal(data, out)
}
