package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRoutesRequireAPIKey(t *testing.T) {
	s := &server{cfg: config{APIKey: "secret-key", AppName: "hpx-node-missing-cli"}}
	mux := newMux(s)

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/"},
		{http.MethodPost, "/node/update"},
		{http.MethodPost, "/node/core_update"},
		{http.MethodPost, "/node/geofiles"},
		{http.MethodPost, "/node/hard_reset"},
	}

	for _, rt := range routes {
		t.Run(rt.method+" "+rt.path+" missing key", func(t *testing.T) {
			req := httptest.NewRequest(rt.method, rt.path, nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d body=%s", rr.Code, rr.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("json: %v", err)
			}
			if body["detail"] != "missing api key" {
				t.Fatalf("unexpected detail: %q", body["detail"])
			}
		})

		t.Run(rt.method+" "+rt.path+" bad key", func(t *testing.T) {
			req := httptest.NewRequest(rt.method, rt.path, nil)
			req.Header.Set("x-api-key", "wrong")
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d body=%s", rr.Code, rr.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("json: %v", err)
			}
			if body["detail"] != "invalid api key" {
				t.Fatalf("unexpected detail: %q", body["detail"])
			}
		})
	}
}

func TestRootOKWithValidKey(t *testing.T) {
	s := &server{cfg: config{APIKey: "secret-key", AppName: "hpx-node"}}
	mux := newMux(s)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("x-api-key", "secret-key")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("unexpected body: %#v", body)
	}
}

func TestCoreUpdateAndGeofilesReturn501WhenCLILacksSubcommands(t *testing.T) {
	// "go" exists but does not advertise core-update / geofiles in help text.
	s := &server{cfg: config{APIKey: "secret-key", AppName: "go"}}
	mux := newMux(s)

	cases := []struct {
		path string
		body string
	}{
		{"/node/core_update", `{"core_version":"v1.2.3"}`},
		{"/node/geofiles", `{"region":"iran"}`},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			req.Header.Set("x-api-key", "secret-key")
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			if rr.Code != http.StatusNotImplemented {
				t.Fatalf("expected 501, got %d body=%s", rr.Code, rr.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("json: %v", err)
			}
			if body["detail"] == "" {
				t.Fatal("expected non-empty detail")
			}
		})
	}
}

func TestRouteRegistration(t *testing.T) {
	s := &server{cfg: config{APIKey: "k", AppName: "missing-binary-xyz"}}
	mux := newMux(s)

	// Registered management routes must not 404 (auth/501 responses are fine).
	paths := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/"},
		{http.MethodPost, "/node/update"},
		{http.MethodPost, "/node/core_update"},
		{http.MethodPost, "/node/geofiles"},
		{http.MethodPost, "/node/hard_reset"},
	}
	for _, p := range paths {
		req := httptest.NewRequest(p.method, p.path, nil)
		req.Header.Set("x-api-key", "k")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code == http.StatusNotFound {
			t.Fatalf("%s %s should be registered, got 404", p.method, p.path)
		}
	}
}
