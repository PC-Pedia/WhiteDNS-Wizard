package xui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
)

type APIClient struct {
	baseURL  string
	basePath string
	http     *http.Client
	csrf     string
}

type apiMessage struct {
	Success bool            `json:"success"`
	Msg     string          `json:"msg"`
	Obj     json.RawMessage `json:"obj"`
}

type httpStatusError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("%s %s returned %d: %s", e.Method, e.Path, e.StatusCode, e.Body)
}

var xrayConfigReadEndpoints = []string{
	"panel/api/xray/",
	"panel/xray/",
}

var xrayConfigUpdateEndpoints = []string{
	"panel/api/xray/update",
	"panel/xray/update",
}

func NewAPIClient(baseURL, basePath string) (*APIClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &APIClient{
		baseURL:  strings.TrimRight(baseURL, "/"),
		basePath: normalizeBasePath(basePath),
		http:     &http.Client{Jar: jar},
	}, nil
}

func normalizeBasePath(basePath string) string {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" || basePath == "/" {
		return "/"
	}
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}
	return basePath
}

func (c *APIClient) Login(ctx context.Context, username, password string) error {
	if err := c.refreshCSRF(ctx, "csrf-token"); err != nil {
		return err
	}
	body := map[string]string{"username": username, "password": password}
	if _, err := c.doJSON(ctx, http.MethodPost, "login", body, nil); err != nil {
		return fmt.Errorf("login to 3x-ui panel: %w", err)
	}
	return nil
}

func (c *APIClient) ListInbounds(ctx context.Context) ([]Inbound, error) {
	var inbounds []Inbound
	if _, err := c.doJSON(ctx, http.MethodGet, "panel/api/inbounds/list", nil, &inbounds); err != nil {
		return nil, err
	}
	return inbounds, nil
}

func (c *APIClient) AddInbound(ctx context.Context, inbound Inbound) (Inbound, error) {
	var created Inbound
	_, err := c.doJSON(ctx, http.MethodPost, "panel/api/inbounds/add", inbound, &created)
	if err != nil {
		return Inbound{}, err
	}
	return created, nil
}

func (c *APIClient) DeleteInbound(ctx context.Context, id int) error {
	_, err := c.doJSON(ctx, http.MethodPost, "panel/api/inbounds/del/"+strconv.Itoa(id), nil, nil)
	return err
}

func (c *APIClient) RestartXray(ctx context.Context) error {
	_, err := c.doJSON(ctx, http.MethodPost, "panel/api/server/restartXrayService", nil, nil)
	return err
}

func (c *APIClient) GetXrayConfig(ctx context.Context) (map[string]any, string, error) {
	var raw json.RawMessage
	if err := c.doFormWithFallback(ctx, xrayConfigReadEndpoints, nil, &raw); err != nil {
		return nil, "", err
	}
	return parseXrayConfig(raw)
}

func parseXrayConfig(raw json.RawMessage) (map[string]any, string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil, "", fmt.Errorf("parse xray setting wrapper: empty response")
	}
	if raw[0] == '"' {
		var encoded string
		if err := json.Unmarshal(raw, &encoded); err != nil {
			return nil, "", fmt.Errorf("parse xray setting wrapper: %w", err)
		}
		raw = []byte(encoded)
	}
	var wrapper struct {
		XraySetting     json.RawMessage `json:"xraySetting"`
		OutboundTestURL string          `json:"outboundTestUrl"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, "", fmt.Errorf("parse xray setting wrapper: %w", err)
	}
	var config map[string]any
	xraySetting := bytes.TrimSpace(wrapper.XraySetting)
	if len(xraySetting) > 0 && xraySetting[0] == '"' {
		var encoded string
		if err := json.Unmarshal(xraySetting, &encoded); err != nil {
			return nil, "", fmt.Errorf("parse xray setting: %w", err)
		}
		xraySetting = []byte(encoded)
	}
	if err := json.Unmarshal(xraySetting, &config); err != nil {
		return nil, "", fmt.Errorf("parse xray setting: %w", err)
	}
	return config, wrapper.OutboundTestURL, nil
}

func (c *APIClient) UpdateXrayConfig(ctx context.Context, config map[string]any, outboundTestURL string) error {
	if outboundTestURL == "" {
		outboundTestURL = "https://www.google.com/generate_204"
	}
	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal xray setting: %w", err)
	}
	values := url.Values{}
	values.Set("xraySetting", string(data))
	values.Set("outboundTestUrl", outboundTestURL)
	return c.doFormWithFallback(ctx, xrayConfigUpdateEndpoints, values, nil)
}

func (c *APIClient) refreshCSRF(ctx context.Context, endpoint string) error {
	var token string
	if _, err := c.doJSON(ctx, http.MethodGet, endpoint, nil, &token); err != nil {
		return fmt.Errorf("get CSRF token: %w", err)
	}
	c.csrf = token
	return nil
}

func (c *APIClient) doJSON(ctx context.Context, method, endpoint string, body any, target any) (apiMessage, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return apiMessage{}, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url(endpoint), reader)
	if err != nil {
		return apiMessage{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" && method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	return c.send(req, target)
}

func (c *APIClient) doForm(ctx context.Context, endpoint string, values url.Values, target any) (apiMessage, error) {
	if values == nil {
		values = url.Values{}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(endpoint), strings.NewReader(values.Encode()))
	if err != nil {
		return apiMessage{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	return c.send(req, target)
}

func (c *APIClient) doFormWithFallback(ctx context.Context, endpoints []string, values url.Values, target any) error {
	for i, endpoint := range endpoints {
		_, err := c.doForm(ctx, endpoint, values, target)
		if err == nil {
			return nil
		}
		if i < len(endpoints)-1 && isMissingRouteError(err) {
			continue
		}
		return err
	}
	return nil
}

func isMissingRouteError(err error) bool {
	var statusErr *httpStatusError
	if !errors.As(err, &statusErr) {
		return false
	}
	return statusErr.StatusCode == http.StatusNotFound || statusErr.StatusCode == http.StatusMethodNotAllowed
}

func (c *APIClient) send(req *http.Request, target any) (apiMessage, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return apiMessage{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return apiMessage{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return apiMessage{}, &httpStatusError{
			Method:     req.Method,
			Path:       req.URL.Path,
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(data)),
		}
	}
	var msg apiMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return apiMessage{}, fmt.Errorf("parse 3x-ui response: %w", err)
	}
	if !msg.Success {
		if msg.Msg == "" {
			msg.Msg = "3x-ui request failed"
		}
		return msg, fmt.Errorf("%s", msg.Msg)
	}
	if target != nil && len(msg.Obj) > 0 && string(msg.Obj) != "null" {
		if err := json.Unmarshal(msg.Obj, target); err != nil {
			return msg, fmt.Errorf("parse 3x-ui object: %w", err)
		}
	}
	return msg, nil
}

func (c *APIClient) url(endpoint string) string {
	endpoint = strings.TrimLeft(endpoint, "/")
	if endpoint == "" {
		return c.baseURL + c.basePath
	}
	return c.baseURL + c.basePath + endpoint
}
