package exchange

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/z4ce/snyk-oidc-exchange/pkg/oidc"
	"github.com/z4ce/snyk-oidc-exchange/pkg/snyk"
)

func TestExchangeToken(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		requestBody   interface{}
		setupEnv      func()
		expectedCode  int
		expectedError string
	}{
		{
			name:   "method not allowed",
			method: http.MethodGet,
			requestBody: TokenRequest{
				Token: "valid-token",
			},
			setupEnv: func() {
				os.Setenv("SNYK_TOKEN", "test-token")
				os.Setenv("SNYK_ORG_ID", "test-org")
				os.Setenv("SNYK_ROLE_ID", "test-role-id")
			},
			expectedCode:  http.StatusMethodNotAllowed,
			expectedError: "Method not allowed\n",
		},
		{
			name:   "missing token",
			method: http.MethodPost,
			requestBody: TokenRequest{
				Token: "",
			},
			setupEnv: func() {
				os.Setenv("SNYK_TOKEN", "test-token")
				os.Setenv("SNYK_ORG_ID", "test-org")
				os.Setenv("SNYK_ROLE_ID", "test-role-id")
			},
			expectedCode:  http.StatusBadRequest,
			expectedError: "missing token in request\n",
		},
		{
			name:   "missing org id",
			method: http.MethodPost,
			requestBody: TokenRequest{
				Token: "valid-token",
			},
			setupEnv: func() {
				os.Setenv("SNYK_TOKEN", "test-token")
				os.Unsetenv("SNYK_ORG_ID")
				os.Setenv("SNYK_ROLE_ID", "test-role-id")
			},
			expectedCode:  http.StatusInternalServerError,
			expectedError: "missing SNYK_ORG_ID environment variable\n",
		},
		{
			name:   "missing role id",
			method: http.MethodPost,
			requestBody: TokenRequest{
				Token: "valid-token",
			},
			setupEnv: func() {
				os.Setenv("SNYK_TOKEN", "test-token")
				os.Setenv("SNYK_ORG_ID", "test-org")
				os.Unsetenv("SNYK_ROLE_ID")
			},
			expectedCode:  http.StatusInternalServerError,
			expectedError: "missing SNYK_ROLE_ID environment variable\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup environment
			if tt.setupEnv != nil {
				tt.setupEnv()
			}
			defer func() {
				os.Unsetenv("SNYK_TOKEN")
				os.Unsetenv("SNYK_ORG_ID")
				os.Unsetenv("SNYK_ROLE_ID")
			}()

			// Create service
			verifier, err := oidc.NewVerifier(context.Background(), "test-owner")
			if err != nil {
				t.Fatalf("failed to create verifier: %v", err)
			}

			service := &Service{
				verifier: verifier,
				snyk:     snyk.NewClient("test-token"),
				roleID:   "test-role-id",
			}

			// Create request
			body, err := json.Marshal(tt.requestBody)
			if err != nil {
				t.Fatalf("failed to marshal request body: %v", err)
			}

			req := httptest.NewRequest(tt.method, "/exchange", bytes.NewReader(body))
			w := httptest.NewRecorder()

			// Call service
			service.ExchangeToken(w, req)

			// Check response
			if w.Code != tt.expectedCode {
				t.Errorf("expected status code %d, got %d", tt.expectedCode, w.Code)
			}

			if w.Body.String() != tt.expectedError {
				t.Errorf("expected error %q, got %q", tt.expectedError, w.Body.String())
			}
		})
	}
}

// Add a separate test for NewService to test environment variable requirements
func TestNewService(t *testing.T) {
	tests := []struct {
		name        string
		setupEnv    func()
		expectError bool
		errorMsg    string
	}{
		{
			name: "missing snyk token",
			setupEnv: func() {
				os.Unsetenv("SNYK_TOKEN")
				os.Setenv("SNYK_ROLE_ID", "test-role-id")
			},
			expectError: true,
			errorMsg:    "missing SNYK_TOKEN environment variable",
		},
		{
			name: "missing role id",
			setupEnv: func() {
				os.Setenv("SNYK_TOKEN", "test-token")
				os.Unsetenv("SNYK_ROLE_ID")
			},
			expectError: true,
			errorMsg:    "missing SNYK_ROLE_ID environment variable",
		},
		{
			name: "valid configuration",
			setupEnv: func() {
				os.Setenv("SNYK_TOKEN", "test-token")
				os.Setenv("SNYK_ROLE_ID", "test-role-id")
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupEnv != nil {
				tt.setupEnv()
			}
			defer func() {
				os.Unsetenv("SNYK_TOKEN")
				os.Unsetenv("SNYK_ROLE_ID")
			}()

			_, err := NewService(context.Background(), "test-owner")
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				} else if err.Error() != tt.errorMsg {
					t.Errorf("expected error message %q, got %q", tt.errorMsg, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
