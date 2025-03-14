package snyk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// testClient extends the Client with test-specific configuration
type testClient struct {
	*Client
	authURL string
	baseURL string
}

func newTestClient(token string, authURL, baseURL string) *testClient {
	return &testClient{
		Client:  NewClient(token),
		authURL: authURL,
		baseURL: baseURL,
	}
}

func (c *testClient) doRequest(ctx context.Context, method, url string, body io.Reader, v interface{}) error {
	httpReq, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add query parameters
	q := httpReq.URL.Query()
	q.Add("version", version)
	httpReq.URL.RawQuery = q.Encode()

	httpReq.Header.Set("Authorization", "token "+c.token)
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
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

func (c *testClient) GetClientCredentialsToken(ctx context.Context, clientID, clientSecret string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.authURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tokenResp, nil
}

func (c *testClient) CreateServiceAccount(ctx context.Context, orgID string, name string, authType string, roleID string, opts ...ServiceAccountOption) (*ServiceAccount, error) {
	url := fmt.Sprintf("%s/orgs/%s/service_accounts", c.baseURL, orgID)

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

func TestGetClientCredentialsToken(t *testing.T) {
	tests := []struct {
		name          string
		clientID      string
		clientSecret  string
		serverStatus  int
		serverResp    *TokenResponse
		expectedError bool
	}{
		{
			name:         "successful token request",
			clientID:     "test-client-id",
			clientSecret: "test-client-secret",
			serverStatus: http.StatusOK,
			serverResp: &TokenResponse{
				AccessToken:      "test-access-token",
				ExpiresIn:        3600,
				RefreshToken:     "test-refresh-token",
				RefreshExpiresIn: 15552000,
				TokenType:        "bearer",
				Scope:            "org.read org.project.read",
				BotID:            "test-bot-id",
			},
			expectedError: false,
		},
		{
			name:          "server error",
			clientID:      "test-client-id",
			clientSecret:  "test-client-secret",
			serverStatus:  http.StatusInternalServerError,
			expectedError: true,
		},
		{
			name:          "invalid credentials",
			clientID:      "invalid-client",
			clientSecret:  "invalid-secret",
			serverStatus:  http.StatusUnauthorized,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request
				if r.Method != http.MethodPost {
					t.Errorf("expected POST request, got %s", r.Method)
				}
				if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
					t.Errorf("expected Content-Type application/x-www-form-urlencoded, got %s", r.Header.Get("Content-Type"))
				}

				// Verify form values
				if err := r.ParseForm(); err != nil {
					t.Fatalf("failed to parse form: %v", err)
				}
				if r.Form.Get("grant_type") != "client_credentials" {
					t.Errorf("expected grant_type=client_credentials, got %s", r.Form.Get("grant_type"))
				}
				if r.Form.Get("client_id") != tt.clientID {
					t.Errorf("expected client_id=%s, got %s", tt.clientID, r.Form.Get("client_id"))
				}
				if r.Form.Get("client_secret") != tt.clientSecret {
					t.Errorf("expected client_secret=%s, got %s", tt.clientSecret, r.Form.Get("client_secret"))
				}

				w.WriteHeader(tt.serverStatus)
				if tt.serverResp != nil {
					json.NewEncoder(w).Encode(tt.serverResp)
				}
			}))
			defer server.Close()

			// Create test client
			client := newTestClient("test-token", server.URL, "")

			// Call the method
			resp, err := client.GetClientCredentialsToken(context.Background(), tt.clientID, tt.clientSecret)

			if tt.expectedError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if resp.AccessToken != tt.serverResp.AccessToken {
				t.Errorf("expected access token %s, got %s", tt.serverResp.AccessToken, resp.AccessToken)
			}
			if resp.TokenType != tt.serverResp.TokenType {
				t.Errorf("expected token type %s, got %s", tt.serverResp.TokenType, resp.TokenType)
			}
			if resp.Scope != tt.serverResp.Scope {
				t.Errorf("expected scope %s, got %s", tt.serverResp.Scope, resp.Scope)
			}
		})
	}
}

func TestCreateServiceAccount(t *testing.T) {
	tests := []struct {
		name          string
		orgID         string
		saName        string
		authType      string
		roleID        string
		serverStatus  int
		serverResp    *CreateServiceAccountResponse
		expectedError bool
	}{
		{
			name:         "successful service account creation",
			orgID:        "test-org",
			saName:       "test-sa",
			authType:     "oauth2",
			roleID:       "test-role",
			serverStatus: http.StatusCreated,
			serverResp: &CreateServiceAccountResponse{
				Data: ServiceAccount{
					ID:   "test-sa-id",
					Type: "service_account",
					Attributes: ServiceAccountAttr{
						Name:     "test-sa",
						AuthType: "oauth2",
						RoleID:   "test-role",
					},
				},
			},
			expectedError: false,
		},
		{
			name:          "server error",
			orgID:         "test-org",
			saName:        "test-sa",
			authType:      "oauth2",
			roleID:        "test-role",
			serverStatus:  http.StatusInternalServerError,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request
				if r.Method != http.MethodPost {
					t.Errorf("expected POST request, got %s", r.Method)
				}
				if r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
				}
				if r.Header.Get("Authorization") != "token test-token" {
					t.Errorf("expected Authorization token test-token, got %s", r.Header.Get("Authorization"))
				}

				// Verify URL contains version parameter
				if r.URL.Query().Get("version") != version {
					t.Errorf("expected version %s, got %s", version, r.URL.Query().Get("version"))
				}

				w.WriteHeader(tt.serverStatus)
				if tt.serverResp != nil {
					json.NewEncoder(w).Encode(tt.serverResp)
				}
			}))
			defer server.Close()

			// Create test client
			client := newTestClient("test-token", "", server.URL)

			// Call the method
			resp, err := client.CreateServiceAccount(context.Background(), tt.orgID, tt.saName, tt.authType, tt.roleID)

			if tt.expectedError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if resp.ID != tt.serverResp.Data.ID {
				t.Errorf("expected service account ID %s, got %s", tt.serverResp.Data.ID, resp.ID)
			}
			if resp.Attributes.Name != tt.serverResp.Data.Attributes.Name {
				t.Errorf("expected name %s, got %s", tt.serverResp.Data.Attributes.Name, resp.Attributes.Name)
			}
		})
	}
}
