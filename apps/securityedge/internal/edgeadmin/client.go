package edgeadmin

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	base  *url.URL
	token string
	http  *http.Client
}

const maxResponseBytes int64 = 16 << 20

func New(rawURL, token string, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(rawURL), "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid edgeproxy admin URL")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	// The Admin API is an internal control-plane dependency. Never send its
	// bearer token through an ambient HTTP(S)_PROXY, and do not follow redirects
	// that could move credentials to an unexpected endpoint.
	transport.Proxy = nil
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Client{base: u, token: token, http: client}, nil
}
func (c *Client) JSON(ctx context.Context, method, path string, query url.Values, body any) (json.RawMessage, int, error) {
	u := *c.base
	u.Path = strings.TrimRight(c.base.Path, "/") + path
	u.RawQuery = query.Encode()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return nil, 0, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := readJSONResponse(resp.Body, resp.ContentLength, maxResponseBytes)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if !json.Valid(data) {
		return nil, resp.StatusCode, fmt.Errorf("edgeproxy returned non-JSON response")
	}
	return json.RawMessage(data), resp.StatusCode, nil
}

func readJSONResponse(body io.Reader, contentLength, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("edgeproxy response limit must be positive")
	}
	// Reject an explicitly oversized response before reading its body. Besides
	// avoiding unnecessary control-plane traffic, this ensures callers receive
	// the intended size-limit error instead of an unrelated client timeout while
	// downloading a response that can never be accepted.
	if contentLength > maxBytes {
		return nil, fmt.Errorf("edgeproxy response exceeds %d bytes", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("edgeproxy response exceeds %d bytes", maxBytes)
	}
	return data, nil
}

// CloseIdleConnections releases keep-alive connections owned by this client.
// Runtime reloads replace the control-plane client, so retiring the old
// transport prevents repeated reloads from retaining idle sockets until their
// transport timeout expires. Active requests are not interrupted.
func (c *Client) CloseIdleConnections() {
	if c == nil || c.http == nil {
		return
	}
	c.http.CloseIdleConnections()
}

func (c *Client) Healthy(ctx context.Context) error {
	_, status, err := c.JSON(ctx, http.MethodGet, "/healthz", nil, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("edgeproxy health returned %d", status)
	}
	return nil
}
