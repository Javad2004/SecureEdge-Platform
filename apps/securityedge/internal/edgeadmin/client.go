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
	u, err := url.Parse(strings.TrimRight(rawURL, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid edgeproxy admin URL")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Client{base: u, token: token, http: &http.Client{Timeout: timeout}}, nil
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, resp.StatusCode, err
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
