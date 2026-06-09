package xui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
)

func TestAPIClientURLPreservesTrailingSlash(t *testing.T) {
	client, err := NewAPIClient("http://127.0.0.1:2053/", "/tp-panel/")
	if err != nil {
		t.Fatalf("NewAPIClient returned error: %v", err)
	}

	got := client.url("panel/xray/")
	want := "http://127.0.0.1:2053/tp-panel/panel/xray/"
	if got != want {
		t.Fatalf("url = %q, want %q", got, want)
	}
}

func TestGetXrayConfigUsesPanelAPIRoute(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Method != http.MethodPost || r.URL.Path != "/tp-panel/panel/api/xray/" {
			http.NotFound(w, r)
			return
		}
		writeXrayConfigResponse(t, w, false)
	}))
	defer server.Close()

	client, err := NewAPIClient(server.URL, "/tp-panel/")
	if err != nil {
		t.Fatalf("NewAPIClient returned error: %v", err)
	}
	config, outboundTestURL, err := client.GetXrayConfig(context.Background())
	if err != nil {
		t.Fatalf("GetXrayConfig returned error: %v", err)
	}
	if outboundTestURL != "https://example.com/generate_204" {
		t.Fatalf("outbound test URL = %q", outboundTestURL)
	}
	if got, _ := config["outbounds"].([]any); len(got) != 0 {
		t.Fatalf("outbounds = %+v, want empty list", got)
	}
	if !reflect.DeepEqual(paths, []string{"/tp-panel/panel/api/xray/"}) {
		t.Fatalf("paths = %+v, want only latest xray API route", paths)
	}
}

func TestGetXrayConfigFallsBackToLegacyRoute(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/tp-panel/panel/api/xray/":
			http.NotFound(w, r)
		case "/tp-panel/panel/xray/":
			writeXrayConfigResponse(t, w, true)
		case "/tp-panel/panel/xray":
			t.Fatalf("client sent slashless legacy xray endpoint")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewAPIClient(server.URL, "/tp-panel/")
	if err != nil {
		t.Fatalf("NewAPIClient returned error: %v", err)
	}
	_, _, err = client.GetXrayConfig(context.Background())
	if err != nil {
		t.Fatalf("GetXrayConfig returned error: %v", err)
	}
	want := []string{"/tp-panel/panel/api/xray/", "/tp-panel/panel/xray/"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths = %+v, want %+v", paths, want)
	}
}

func TestUpdateXrayConfigFallsBackToLegacyRoute(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/tp-panel/panel/api/xray/update":
			http.NotFound(w, r)
		case "/tp-panel/panel/xray/update":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm returned error: %v", err)
			}
			if r.Form.Get("outboundTestUrl") != "https://example.com/generate_204" {
				t.Fatalf("outboundTestUrl = %q", r.Form.Get("outboundTestUrl"))
			}
			var config map[string]any
			if err := json.Unmarshal([]byte(r.Form.Get("xraySetting")), &config); err != nil {
				t.Fatalf("xraySetting was not JSON: %v", err)
			}
			writeAPIMessage(w, "")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewAPIClient(server.URL, "/tp-panel/")
	if err != nil {
		t.Fatalf("NewAPIClient returned error: %v", err)
	}
	err = client.UpdateXrayConfig(context.Background(), map[string]any{"outbounds": []any{}}, "https://example.com/generate_204")
	if err != nil {
		t.Fatalf("UpdateXrayConfig returned error: %v", err)
	}
	want := []string{"/tp-panel/panel/api/xray/update", "/tp-panel/panel/xray/update"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths = %+v, want %+v", paths, want)
	}
}

func TestXrayRouteFallbackSkipsNonRouteErrors(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/tp-panel/panel/api/xray/" {
			http.Error(w, "temporary backend error", http.StatusInternalServerError)
			return
		}
		writeXrayConfigResponse(t, w, true)
	}))
	defer server.Close()

	client, err := NewAPIClient(server.URL, "/tp-panel/")
	if err != nil {
		t.Fatalf("NewAPIClient returned error: %v", err)
	}
	_, _, err = client.GetXrayConfig(context.Background())
	if err == nil {
		t.Fatal("GetXrayConfig returned nil error, want 500")
	}
	if !reflect.DeepEqual(paths, []string{"/tp-panel/panel/api/xray/"}) {
		t.Fatalf("paths = %+v, want no legacy fallback on 500", paths)
	}
}

func writeXrayConfigResponse(t *testing.T, w http.ResponseWriter, encodeWrapperAsString bool) {
	t.Helper()
	wrapper := map[string]any{
		"xraySetting":     map[string]any{"outbounds": []any{}},
		"outboundTestUrl": "https://example.com/generate_204",
	}
	if encodeWrapperAsString {
		data, err := json.Marshal(wrapper)
		if err != nil {
			t.Fatalf("Marshal returned error: %v", err)
		}
		writeAPIMessage(w, string(data))
		return
	}
	writeAPIMessage(w, wrapper)
}

func writeAPIMessage(w http.ResponseWriter, obj any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"obj":     obj,
	})
}

func TestParseXrayConfigAcceptsStringXraySetting(t *testing.T) {
	wrapper := map[string]any{
		"xraySetting":     `{"outbounds":[]}`,
		"outboundTestUrl": "https://example.com/generate_204",
	}
	data, err := json.Marshal(wrapper)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	config, outboundTestURL, err := parseXrayConfig(data)
	if err != nil {
		t.Fatalf("parseXrayConfig returned error: %v", err)
	}
	if outboundTestURL != "https://example.com/generate_204" {
		t.Fatalf("outbound test URL = %q", outboundTestURL)
	}
	if _, ok := config["outbounds"].([]any); !ok {
		t.Fatalf("config outbounds type = %T, want []any", config["outbounds"])
	}
}

func TestDoFormWithFallbackAcceptsMethodNotAllowedAsMissingRoute(t *testing.T) {
	var values []url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tp-panel/panel/api/xray/update":
			w.WriteHeader(http.StatusMethodNotAllowed)
		case "/tp-panel/panel/xray/update":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm returned error: %v", err)
			}
			values = append(values, r.Form)
			writeAPIMessage(w, "")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewAPIClient(server.URL, "/tp-panel/")
	if err != nil {
		t.Fatalf("NewAPIClient returned error: %v", err)
	}
	err = client.UpdateXrayConfig(context.Background(), map[string]any{"outbounds": []any{}}, "")
	if err != nil {
		t.Fatalf("UpdateXrayConfig returned error: %v", err)
	}
	if len(values) != 1 {
		t.Fatalf("legacy form submissions = %d, want 1", len(values))
	}
}
