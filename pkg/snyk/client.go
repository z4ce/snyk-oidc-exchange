package snyk

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

const (
	baseURL = "https://api.snyk.io/rest"
	version = "2024-10-15"
	authURL = "https://api.snyk.io/oauth2/token"
)

type Client struct {
	httpClient *http.Client
	token      string
}

type ServiceAccount struct {
	ID         string             `json:"id"`
	Type       string             `json:"type"`
	Attributes ServiceAccountAttr `json:"attributes"`
}

type ServiceAccountAttr struct {
	Name           string `json:"name"`
	AuthType       string `json:"auth_type"`
	RoleID         string `json:"role_id"`
	AccessTokenTTL int    `json:"access_token_ttl_seconds,omitempty"`
	JWKsURL        string `json:"jwks_url,omitempty"`
	APIKey         string `json:"api_key,omitempty"`
	ClientID       string `json:"client_id,omitempty"`
	ClientSecret   string `json:"client_secret,omitempty"`
	Level          string `json:"level,omitempty"`
}

type CreateServiceAccountRequest struct {
	Data CreateServiceAccountData `json:"data"`
}

type CreateServiceAccountData struct {
	Type       string                   `json:"type"`
	Attributes CreateServiceAccountAttr `json:"attributes"`
}

type CreateServiceAccountAttr struct {
	Name           string `json:"name"`
	AuthType       string `json:"auth_type"`
	RoleID         string `json:"role_id"`
	AccessTokenTTL int    `json:"access_token_ttl_seconds,omitempty"`
	JWKsURL        string `json:"jwks_url,omitempty"`
}

type CreateServiceAccountResponse struct {
	Data    ServiceAccount `json:"data"`
	JsonAPI struct {
		Version string `json:"version"`
	} `json:"jsonapi"`
}

type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	BotID            string `json:"bot_id"`
}

type ServiceAccountListResponse struct {
	Data    []ServiceAccount `json:"data"`
	JsonAPI struct {
		Version string `json:"version"`
	} `json:"jsonapi"`
	Links struct {
		First   string `json:"first,omitempty"`
		Last    string `json:"last,omitempty"`
		Next    string `json:"next,omitempty"`
		Prev    string `json:"prev,omitempty"`
		Related string `json:"related,omitempty"`
		Self    string `json:"self,omitempty"`
	} `json:"links,omitempty"`
}

type ServiceAccountOption func(*CreateServiceAccountAttr)

func WithAccessTokenTTL(ttl int) ServiceAccountOption {
	return func(attr *CreateServiceAccountAttr) {
		if ttl >= 3600 && ttl <= 86400 {
			attr.AccessTokenTTL = ttl
		}
	}
}

func WithJWKsURL(url string) ServiceAccountOption {
	return func(attr *CreateServiceAccountAttr) {
		attr.JWKsURL = url
	}
}

func NewClient(token string) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		token: token,
	}
}

func (c *Client) doRequest(ctx context.Context, method, url string, body io.Reader, v interface{}) error {
	httpReq, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add query parameters
	q := httpReq.URL.Query()
	q.Add("version", version)
	httpReq.URL.RawQuery = q.Encode()

	httpReq.Header.Set("Authorization", "token "+c.token)
	// Always set Content-Type for POST/PUT requests
	if method == http.MethodPost || method == http.MethodPut {
		httpReq.Header.Set("Content-Type", "application/vnd.api+json")
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status code %s: %d", httpReq.URL.String(), resp.StatusCode)
	}

	if v != nil {
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

func (c *Client) CreateServiceAccount(ctx context.Context, orgID string, name string, authType string, roleID string, opts ...ServiceAccountOption) (*ServiceAccount, error) {
	url := fmt.Sprintf("%s/orgs/%s/service_accounts", baseURL, orgID)

	attributes := CreateServiceAccountAttr{
		Name:     name,
		AuthType: authType,
		RoleID:   roleID,
	}

	// Apply any options
	for _, opt := range opts {
		opt(&attributes)
	}

	req := CreateServiceAccountRequest{
		Data: CreateServiceAccountData{
			Type:       "service_account",
			Attributes: attributes,
		},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	var saResponse CreateServiceAccountResponse
	if err := c.doRequest(ctx, http.MethodPost, url, bytes.NewReader(body), &saResponse); err != nil {
		return nil, err
	}

	return &saResponse.Data, nil
}

func (c *Client) CreateToken(ctx context.Context, clientID, clientSecret string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Log request details (excluding sensitive data)
	fmt.Printf("Making token request to: %s\n", authURL)
	fmt.Printf("Request body: %s\n", data.Encode())
	fmt.Printf("Request headers: Content-Type=%s\n", req.Header.Get("Content-Type"))
	fmt.Printf("Request body length: %d bytes\n", len(data.Encode()))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token request failed with status %d\nResponse headers: %v\nResponse body: %s",
			resp.StatusCode,
			resp.Header,
			string(bodyBytes))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tokenResp, nil
}

func (c *Client) GetServiceAccount(ctx context.Context, orgID string, name string) (*ServiceAccount, error) {
	url := fmt.Sprintf("%s/orgs/%s/service_accounts", baseURL, orgID)

	var response ServiceAccountListResponse
	if err := c.doRequest(ctx, http.MethodGet, url, nil, &response); err != nil {
		return nil, err
	}

	for _, account := range response.Data {
		if account.Attributes.Name == name {
			return &account, nil
		}
	}

	return nil, nil
}
