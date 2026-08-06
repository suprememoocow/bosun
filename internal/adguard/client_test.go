package adguard

import (
	"context"
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

func TestWriteStubs(t *testing.T) {
	c, _ := New("http://localhost", "", "")
	ctx := context.Background()
	if err := c.AddClient(ctx, PersistentClient{}); err != ErrNotImplemented {
		t.Errorf("AddClient = %v, want ErrNotImplemented", err)
	}
	if err := c.DeleteRewrite(ctx, Rewrite{}); err != ErrNotImplemented {
		t.Errorf("DeleteRewrite = %v, want ErrNotImplemented", err)
	}
}
