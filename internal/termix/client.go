package termix

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

type Options struct {
	Token              string
	InsecureSkipVerify bool
	CAFile             string
	HTTPClient         *http.Client
}

type User struct {
	UserID       string `json:"userId"`
	Username     string `json:"username"`
	IsAdmin      bool   `json:"is_admin"`
	IsOIDC       bool   `json:"is_oidc"`
	IsDualAuth   bool   `json:"is_dual_auth"`
	TOTPEnabled  bool   `json:"totp_enabled"`
	DataUnlocked bool   `json:"data_unlocked"`
}

func NewClient(rawURL string, opts Options) (*Client, error) {
	baseURL, err := NormalizeBaseURL(rawURL)
	if err != nil {
		return nil, err
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	if opts.InsecureSkipVerify || strings.TrimSpace(opts.CAFile) != "" {
		transport, err := transportForTLSOptions(opts.InsecureSkipVerify, opts.CAFile)
		if err != nil {
			return nil, err
		}
		httpClient = &http.Client{
			Timeout:   httpClient.Timeout,
			Transport: transport,
		}
	}
	return &Client{
		baseURL:    baseURL,
		token:      strings.TrimSpace(opts.Token),
		httpClient: httpClient,
	}, nil
}

func NormalizeBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("url is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("backend url must use http or https: %s", raw)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("backend url must include a host: %s", raw)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func (c *Client) Health(ctx context.Context) error {
	req, err := c.newRequest(ctx, http.MethodGet, "/health")
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("termix health check returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) CurrentUser(ctx context.Context) (User, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/users/me")
	if err != nil {
		return User{}, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return User{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return User{}, fmt.Errorf("termix user validation returned HTTP %d", resp.StatusCode)
	}
	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return User{}, err
	}
	return user, nil
}

func (c *Client) newRequest(ctx context.Context, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func transportForTLSOptions(insecure bool, caFile string) (*http.Transport, error) {
	cfg := &tls.Config{InsecureSkipVerify: insecure} //nolint:gosec // Explicit user opt-in for self-hosted Termix instances.
	caFile = strings.TrimSpace(caFile)
	if caFile != "" {
		raw, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("failed to read CA certificates from %s", caFile)
		}
		cfg.RootCAs = pool
	}
	return &http.Transport{TLSClientConfig: cfg}, nil
}
