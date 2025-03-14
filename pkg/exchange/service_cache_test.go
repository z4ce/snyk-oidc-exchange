package exchange

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/z4ce/snyk-oidc-exchange/pkg/oidc"
	"github.com/z4ce/snyk-oidc-exchange/pkg/snyk"
)

// MockSnykClient is a mock implementation of the Snyk client for testing
type MockSnykClient struct {
	getServiceAccountCalled        bool
	createServiceAccountCalled     bool
	deleteServiceAccountCalled     bool
	createTokenCalled              bool
	mockServiceAccount             *snyk.ServiceAccount
	mockTokenResponse              *snyk.TokenResponse
	shouldFailGetServiceAccount    bool
	shouldFailCreateServiceAccount bool
	shouldFailDeleteServiceAccount bool
	shouldFailCreateToken          bool
}

func NewMockSnykClient() *MockSnykClient {
	return &MockSnykClient{
		mockServiceAccount: &snyk.ServiceAccount{
			ID:   "test-service-account-id",
			Type: "service_account",
			Attributes: snyk.ServiceAccountAttr{
				Name:         "github-oidcexchange-testorg",
				AuthType:     "oauth_client_secret",
				RoleID:       "test-role-id",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		},
		mockTokenResponse: &snyk.TokenResponse{
			AccessToken:      "test-access-token",
			ExpiresIn:        600,
			RefreshToken:     "test-refresh-token",
			RefreshExpiresIn: 86400,
			TokenType:        "bearer",
			Scope:            "org.read",
		},
	}
}

func (m *MockSnykClient) GetServiceAccount(ctx context.Context, orgID string, name string) (*snyk.ServiceAccount, error) {
	m.getServiceAccountCalled = true

	if m.shouldFailGetServiceAccount {
		return nil, &mockError{"Failed to get service account"}
	}

	if name == "github-oidcexchange-testorg" {
		return m.mockServiceAccount, nil
	}

	return nil, nil
}

func (m *MockSnykClient) CreateServiceAccount(ctx context.Context, orgID string, name string, authType string, roleID string, opts ...snyk.ServiceAccountOption) (*snyk.ServiceAccount, error) {
	m.createServiceAccountCalled = true

	if m.shouldFailCreateServiceAccount {
		return nil, &mockError{"Failed to create service account"}
	}

	return m.mockServiceAccount, nil
}

func (m *MockSnykClient) DeleteServiceAccount(ctx context.Context, orgID string, serviceAccountID string) error {
	m.deleteServiceAccountCalled = true

	if m.shouldFailDeleteServiceAccount {
		return &mockError{"Failed to delete service account"}
	}

	return nil
}

func (m *MockSnykClient) CreateToken(ctx context.Context, clientID, clientSecret string) (*snyk.TokenResponse, error) {
	m.createTokenCalled = true

	if m.shouldFailCreateToken {
		return nil, &mockError{"Failed to create token"}
	}

	return m.mockTokenResponse, nil
}

// mockError is a simple error implementation for tests
type mockError struct {
	message string
}

func (e *mockError) Error() string {
	return e.message
}

// mockVerifier is a mock implementation of the OIDC verifier for testing
type mockVerifier struct{}

func (v *mockVerifier) VerifyToken(ctx context.Context, tokenString string) (*oidc.Claims, error) {
	return &oidc.Claims{
		Repository:           "testorg/testrepo",
		RepositoryOwner:      "testorg",
		WorkflowRef:          "testorg/testrepo/.github/workflows/test.yml@main",
		RepositoryVisibility: "private",
	}, nil
}

func TestServiceCacheHitAndMiss(t *testing.T) {
	tests := []struct {
		name                         string
		setupService                 func() (*Service, *MockSnykClient)
		firstRequestShouldFail       bool
		secondRequestShouldFail      bool
		expectGetCalledFirstTime     bool
		expectCreateCalledFirstTime  bool
		expectDeleteCalledFirstTime  bool
		expectGetCalledSecondTime    bool
		expectCreateCalledSecondTime bool
		expectDeleteCalledSecondTime bool
	}{
		{
			name: "cache miss then hit",
			setupService: func() (*Service, *MockSnykClient) {
				mockClient := NewMockSnykClient()
				service := &Service{
					verifier:   &mockVerifier{},
					snyk:       mockClient,
					roleID:     "test-role-id",
					credCache:  make(map[string]ServiceAccountCredentials),
					cacheMutex: sync.RWMutex{},
				}
				return service, mockClient
			},
			firstRequestShouldFail:       false,
			secondRequestShouldFail:      false,
			expectGetCalledFirstTime:     true,
			expectCreateCalledFirstTime:  true,
			expectDeleteCalledFirstTime:  true,
			expectGetCalledSecondTime:    false,
			expectCreateCalledSecondTime: false,
			expectDeleteCalledSecondTime: false,
		},
		{
			name: "cache hit then token creation failure",
			setupService: func() (*Service, *MockSnykClient) {
				mockClient := NewMockSnykClient()
				service := &Service{
					verifier:   &mockVerifier{},
					snyk:       mockClient,
					roleID:     "test-role-id",
					credCache:  make(map[string]ServiceAccountCredentials),
					cacheMutex: sync.RWMutex{},
				}

				// Pre-populate the cache
				service.cacheCredentials("github-oidcexchange-testorg", ServiceAccountCredentials{
					ID:           "test-service-account-id",
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				})

				return service, mockClient
			},
			firstRequestShouldFail:      false,
			secondRequestShouldFail:     true,
			expectGetCalledFirstTime:    false,
			expectCreateCalledFirstTime: false,
			expectDeleteCalledFirstTime: false,
			// Note: When token creation fails, we remove from cache but don't immediately try to recreate
			// This will happen on the next request
			expectGetCalledSecondTime:    false,
			expectCreateCalledSecondTime: false,
			expectDeleteCalledSecondTime: false,
		},
	}

	os.Setenv("SNYK_ORG_ID", "test-org-id")
	os.Setenv("SNYK_ROLE_ID", "test-role-id")
	defer func() {
		os.Unsetenv("SNYK_ORG_ID")
		os.Unsetenv("SNYK_ROLE_ID")
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, mockClient := tt.setupService()

			// First request
			req1 := httptest.NewRequest(http.MethodPost, "/exchange",
				bytes.NewReader([]byte(`{"token": "test-token"}`)))
			w1 := httptest.NewRecorder()

			service.ExchangeToken(w1, req1)

			// Verify first response
			if tt.firstRequestShouldFail {
				if w1.Code != http.StatusInternalServerError {
					t.Errorf("expected first request to fail with 500, got %d", w1.Code)
				}
			} else {
				if w1.Code != http.StatusOK {
					t.Errorf("expected first request to succeed with 200, got %d: %s", w1.Code, w1.Body.String())
				}

				var resp1 TokenResponse
				if err := json.NewDecoder(w1.Body).Decode(&resp1); err != nil {
					t.Fatalf("failed to decode first response: %v", err)
				}

				if resp1.Token != "test-access-token" {
					t.Errorf("expected token test-access-token, got %s", resp1.Token)
				}
			}

			// Verify first request's API calls
			if mockClient.getServiceAccountCalled != tt.expectGetCalledFirstTime {
				t.Errorf("expected GetServiceAccount to be called %v on first request, got %v",
					tt.expectGetCalledFirstTime, mockClient.getServiceAccountCalled)
			}

			if mockClient.createServiceAccountCalled != tt.expectCreateCalledFirstTime {
				t.Errorf("expected CreateServiceAccount to be called %v on first request, got %v",
					tt.expectCreateCalledFirstTime, mockClient.createServiceAccountCalled)
			}

			if mockClient.deleteServiceAccountCalled != tt.expectDeleteCalledFirstTime {
				t.Errorf("expected DeleteServiceAccount to be called %v on first request, got %v",
					tt.expectDeleteCalledFirstTime, mockClient.deleteServiceAccountCalled)
			}

			// Reset mock flags for second request
			mockClient.getServiceAccountCalled = false
			mockClient.createServiceAccountCalled = false
			mockClient.deleteServiceAccountCalled = false
			mockClient.createTokenCalled = false

			// Configure mock failures for second request if needed
			if tt.secondRequestShouldFail {
				mockClient.shouldFailCreateToken = true
			}

			// Second request
			req2 := httptest.NewRequest(http.MethodPost, "/exchange",
				bytes.NewReader([]byte(`{"token": "test-token"}`)))
			w2 := httptest.NewRecorder()

			service.ExchangeToken(w2, req2)

			// Verify second response
			if tt.secondRequestShouldFail {
				if w2.Code != http.StatusInternalServerError {
					t.Errorf("expected second request to fail with 500, got %d", w2.Code)
				}

				// After token creation failure, the credentials should be removed from cache
				creds, exists := service.getCredentialsFromCache("github-oidcexchange-testorg")
				if exists {
					t.Errorf("expected credentials to be removed from cache after token failure, but still exists: %+v", creds)
				}
			} else {
				if w2.Code != http.StatusOK {
					t.Errorf("expected second request to succeed with 200, got %d", w2.Code)
				}

				var resp2 TokenResponse
				if err := json.NewDecoder(w2.Body).Decode(&resp2); err != nil {
					t.Fatalf("failed to decode second response: %v", err)
				}

				if resp2.Token != "test-access-token" {
					t.Errorf("expected token test-access-token, got %s", resp2.Token)
				}
			}

			// Verify second request's API calls
			if mockClient.getServiceAccountCalled != tt.expectGetCalledSecondTime {
				t.Errorf("expected GetServiceAccount to be called %v on second request, got %v",
					tt.expectGetCalledSecondTime, mockClient.getServiceAccountCalled)
			}

			if mockClient.createServiceAccountCalled != tt.expectCreateCalledSecondTime {
				t.Errorf("expected CreateServiceAccount to be called %v on second request, got %v",
					tt.expectCreateCalledSecondTime, mockClient.createServiceAccountCalled)
			}

			if mockClient.deleteServiceAccountCalled != tt.expectDeleteCalledSecondTime {
				t.Errorf("expected DeleteServiceAccount to be called %v on second request, got %v",
					tt.expectDeleteCalledSecondTime, mockClient.deleteServiceAccountCalled)
			}

			// For the failure case, we also need to check that a third request would use the API
			if tt.secondRequestShouldFail {
				// Reset mock flags for third request
				mockClient.getServiceAccountCalled = false
				mockClient.createServiceAccountCalled = false
				mockClient.deleteServiceAccountCalled = false
				mockClient.createTokenCalled = false
				mockClient.shouldFailCreateToken = false

				// Third request after a failure should recreate the service account
				req3 := httptest.NewRequest(http.MethodPost, "/exchange",
					bytes.NewReader([]byte(`{"token": "test-token"}`)))
				w3 := httptest.NewRecorder()

				service.ExchangeToken(w3, req3)

				// Now the API calls should happen since the cache was cleared
				if !mockClient.getServiceAccountCalled {
					t.Errorf("expected GetServiceAccount to be called on third request after cache failure")
				}

				if !mockClient.createServiceAccountCalled {
					t.Errorf("expected CreateServiceAccount to be called on third request after cache failure")
				}

				if !mockClient.deleteServiceAccountCalled {
					t.Errorf("expected DeleteServiceAccount to be called on third request after cache failure")
				}
			}
		})
	}
}
