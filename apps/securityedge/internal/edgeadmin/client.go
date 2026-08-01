package edgeadmin

import (
	"bytes"
	"context"
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

func New(rawURL, token string, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(rawURL), "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid edgeproxy admin URL")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
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
	const maxResponseBytes = 16 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(data) > maxResponseBytes {
		return nil, resp.StatusCode, fmt.Errorf("edgeproxy response exceeds %d bytes", maxResponseBytes)
	}
	if !json.Valid(data) {
		return nil, resp.StatusCode, fmt.Errorf("edgeproxy returned non-JSON response")
	}
	return json.RawMessage(data), resp.StatusCode, nil
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
