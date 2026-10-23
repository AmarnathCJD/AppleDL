// Package applemusic implements authentication protocol components observed in
// Apple Music for Android 7.0.0-beta (1606). Package music provides the
// high-level client; see README.md for supported flows and limitations.
package applemusic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"howett.net/plist"
)

// DefaultGrandSlamURL is the production gsService URL returned by this app's
// IdMS static bag. Config.GrandSlamURL can override it with a trusted bag value.
const DefaultGrandSlamURL = "https://gsd.apple.com/grandslam/GsService2"
const maxResponseBytes = 4 << 20

// Config keeps identity headers explicit: device identity must come from the
// same environment that provides Anisette data.
type Config struct {
	HTTPClient   *http.Client
	GrandSlamURL string
	Headers      http.Header
}

type Client struct {
	http         *http.Client
	grandSlamURL string
	headers      http.Header
}

func New(config Config) (*Client, error) {
	endpoint := config.GrandSlamURL
	if endpoint == "" {
		endpoint = DefaultGrandSlamURL
	}
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}
	var hc http.Client
	if config.HTTPClient != nil {
		hc = *config.HTTPClient
	} else {
		client, err := defaultHTTPClient()
		if err != nil {
			return nil, err
		}
		hc = *client
	}
	// Redirects can change the operation or leak a credential to another host.
	// The caller must explicitly decide how to handle a store redirect.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	headers := config.Headers.Clone()
	if headers == nil {
		headers = make(http.Header)
	}
	return &Client{http: &hc, grandSlamURL: endpoint, headers: headers}, nil
}

func validateEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("invalid authentication endpoint")
	}
	if u.Scheme != "https" {
		return errors.New("authentication endpoint must use HTTPS")
	}
	return nil
}

// HTTPError intentionally excludes response bodies, URLs and identity headers.
type HTTPError struct{ StatusCode int }

func (e *HTTPError) Error() string { return fmt.Sprintf("authentication HTTP status %d", e.StatusCode) }

type RedirectError struct {
	StatusCode int
	Location   string
}

func (e *RedirectError) Error() string {
	return fmt.Sprintf("authentication redirect requires handling (HTTP %d)", e.StatusCode)
}

func (c *Client) postPlist(ctx context.Context, endpoint string, body any, headers http.Header, out any) (http.Header, error) {
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}
	data, err := plist.Marshal(body, plist.XMLFormat)
	if err != nil {
		return nil, fmt.Errorf("encode authentication plist: %w", err)
	}
	data, responseHeaders, err := c.post(ctx, endpoint, data, "application/x-apple-plist", headers)
	if err != nil {
		return responseHeaders, err
	}
	if _, err := plist.Unmarshal(data, out); err != nil {
		return nil, errors.New("invalid authentication plist response")
	}
	return responseHeaders, nil
}

func (c *Client) postJSON(ctx context.Context, body any, headers http.Header, out any) (http.Header, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, errors.New("encode authentication JSON failed")
	}
	data, responseHeaders, err := c.post(ctx, c.grandSlamURL, data, "application/json; charset=UTF-8", headers)
	if err != nil {
		return responseHeaders, err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return nil, errors.New("invalid authentication JSON response")
	}
	return responseHeaders, nil
}

func (c *Client) post(ctx context.Context, endpoint string, data []byte, contentType string, headers http.Header) ([]byte, http.Header, error) {
	req, err := c.newPostRequest(ctx, endpoint, data, contentType, headers)
	if err != nil {
		return nil, nil, err
	}
	return c.send(req)
}

func (c *Client) newPostRequest(ctx context.Context, endpoint string, data []byte, contentType string, headers http.Header) (*http.Request, error) {
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("create authentication request failed")
	}
	req.Header = c.headers.Clone()
	for key, values := range headers {
		req.Header[http.CanonicalHeaderKey(key)] = append([]string(nil), values...)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "*/*")
	return req, nil
}

func (c *Client) send(req *http.Request) ([]byte, http.Header, error) {
	data, headers, _, err := c.sendWithStatus(req)
	return data, headers, err
}

func (c *Client) sendWithStatus(req *http.Request) ([]byte, http.Header, int, error) {
	ctx := req.Context()
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, 0, ctx.Err()
		}
		return nil, nil, 0, errors.New("authentication transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, resp.Header.Clone(), resp.StatusCode, &RedirectError{resp.StatusCode, resp.Header.Get("Location")}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.Header.Clone(), resp.StatusCode, &HTTPError{resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		clear(data)
		return nil, nil, resp.StatusCode, errors.New("read authentication response failed")
	}
	if len(data) > maxResponseBytes {
		clear(data)
		return nil, nil, resp.StatusCode, errors.New("authentication response exceeds size limit")
	}
	return data, resp.Header.Clone(), resp.StatusCode, nil
}
