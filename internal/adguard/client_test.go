package adguard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListClientsAndRewrites(t *testing.T) {
	var sawBasicAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); ok && u == "admin" && p == "pw" {
			sawBasicAuth = true
		}
		switch r.URL.Path {
		case "/control/clients":
			w.Write([]byte(`{"clients":[{"name":"nas","ids":["192.168.0.10"],"tags":["device_nas"]}],"auto_clients":[{"name":"auto","ids":["192.168.0.99"]}]}`))
		case "/control/rewrite/list":
			w.Write([]byte(`[{"domain":"nas.example.com","answer":"192.168.0.10"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c, err := New(srv.URL, "admin", "pw", WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	clients, err := c.ListClients(ctx)
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(clients) != 1 || clients[0].Name != "nas" || clients[0].IDs[0] != "192.168.0.10" {
		t.Errorf("unexpected clients: %+v", clients)
	}
	if !sawBasicAuth {
		t.Error("expected basic auth on request")
	}

	rewrites, err := c.ListRewrites(ctx)
	if err != nil {
		t.Fatalf("ListRewrites: %v", err)
	}
	if len(rewrites) != 1 || rewrites[0].Domain != "nas.example.com" {
		t.Errorf("unexpected rewrites: %+v", rewrites)
	}
}

func TestListClientsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	c, _ := New(srv.URL, "admin", "pw", WithHTTPClient(srv.Client()))
	if _, err := c.ListClients(context.Background()); err == nil {
		t.Fatal("expected error on 403")
	}
}

func TestRemainingStubs(t *testing.T) {
	c, _ := New("http://localhost", "", "")
	ctx := context.Background()
	if err := c.DeleteClient(ctx, "x"); err != ErrNotImplemented {
		t.Errorf("DeleteClient = %v, want ErrNotImplemented", err)
	}
	if err := c.DeleteRewrite(ctx, Rewrite{}); err != ErrNotImplemented {
		t.Errorf("DeleteRewrite = %v, want ErrNotImplemented", err)
	}
}

func TestAddClient(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, _ := New(srv.URL, "admin", "pw", WithHTTPClient(srv.Client()))
	if err := c.AddClient(context.Background(), PersistentClient{Name: "nas", IDs: []string{"192.168.0.10"}}); err != nil {
		t.Fatalf("AddClient: %v", err)
	}
	if gotPath != "/control/clients/add" {
		t.Errorf("path = %q", gotPath)
	}
	if gotBody["name"] != "nas" {
		t.Errorf("name = %v", gotBody["name"])
	}
	// A new client inherits global filtering rather than starting unprotected.
	if gotBody["use_global_settings"] != true {
		t.Errorf("use_global_settings = %v, want true", gotBody["use_global_settings"])
	}
}

func TestUpdateClientOverlayPreservesUnmanagedFields(t *testing.T) {
	// Live client carries fields the tool does not manage; the update must keep
	// them and change only ids (design doc §7.3 full-replacement safety).
	live := PersistentClient{}
	if err := json.Unmarshal([]byte(`{
		"name":"nas",
		"ids":["192.168.0.11"],
		"tags":["device_nas"],
		"blocked_services":["youtube"],
		"upstreams":["1.1.1.1"],
		"use_global_settings":false
	}`), &live); err != nil {
		t.Fatal(err)
	}

	var sent struct {
		Name string                     `json:"name"`
		Data map[string]json.RawMessage `json:"data"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/control/clients/update" {
			http.NotFound(w, r)
			return
		}
		json.NewDecoder(r.Body).Decode(&sent)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, _ := New(srv.URL, "admin", "pw", WithHTTPClient(srv.Client()))
	if err := c.UpdateClient(context.Background(), live, []string{"192.168.0.10", "aa:bb:cc:dd:ee:ff"}); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}

	if sent.Name != "nas" {
		t.Errorf("name = %q", sent.Name)
	}
	// ids overlaid...
	var ids []string
	json.Unmarshal(sent.Data["ids"], &ids)
	if len(ids) != 2 || ids[0] != "192.168.0.10" {
		t.Errorf("ids = %v", ids)
	}
	// ...unmanaged fields preserved verbatim.
	for _, key := range []string{"blocked_services", "upstreams", "tags"} {
		if _, ok := sent.Data[key]; !ok {
			t.Errorf("update dropped unmanaged field %q", key)
		}
	}
	var blocked []string
	json.Unmarshal(sent.Data["blocked_services"], &blocked)
	if len(blocked) != 1 || blocked[0] != "youtube" {
		t.Errorf("blocked_services = %v, want [youtube]", blocked)
	}
}
