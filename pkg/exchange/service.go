package exchange

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"

	"z4ce.com/snyk-oidc-exchange/pkg/oidc"
	"z4ce.com/snyk-oidc-exchange/pkg/snyk"
)

var (
	ErrMissingToken       = errors.New("missing token in request")
	ErrMissingSnykToken   = errors.New("missing SNYK_TOKEN environment variable")
	ErrMissingOrgID       = errors.New("missing SNYK_ORG_ID environment variable")
	ErrMissingRoleID      = errors.New("missing SNYK_ROLE_ID environment variable")
	ErrInvalidRequestBody = errors.New("invalid request body")
)

type TokenRequest struct {
	Token string `json:"token"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

// SnykClientInterface defines the interface for the Snyk client
type SnykClientInterface interface {
	GetServiceAccount(ctx context.Context, orgID string, name string) (*snyk.ServiceAccount, error)
	CreateServiceAccount(ctx context.Context, orgID string, name string, authType string, roleID string, opts ...snyk.ServiceAccountOption) (*snyk.ServiceAccount, error)
	DeleteServiceAccount(ctx context.Context, orgID string, serviceAccountID string) error
	CreateToken(ctx context.Context, clientID, clientSecret string) (*snyk.TokenResponse, error)
}

// OIDCVerifierInterface defines the interface for the OIDC verifier
type OIDCVerifierInterface interface {
	VerifyToken(ctx context.Context, tokenString string) (*oidc.Claims, error)
}

// ServiceAccountCredentials represents the credentials for a service account
type ServiceAccountCredentials struct {
	ID           string
	ClientID     string
	ClientSecret string
}

type Service struct {
	verifier   OIDCVerifierInterface
	snyk       SnykClientInterface
	roleID     string
	credCache  map[string]ServiceAccountCredentials
	cacheMutex sync.RWMutex
}

func NewService(ctx context.Context, allowedOwner string) (*Service, error) {
	verifier, err := oidc.NewVerifier(ctx, allowedOwner)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	snykToken := os.Getenv("SNYK_TOKEN")
	if snykToken == "" {
		return nil, ErrMissingSnykToken
	}

	roleID := os.Getenv("SNYK_ROLE_ID")
	if roleID == "" {
		return nil, ErrMissingRoleID
	}

	return &Service{
		verifier:   verifier,
		snyk:       snyk.NewClient(snykToken),
		roleID:     roleID,
		credCache:  make(map[string]ServiceAccountCredentials),
		cacheMutex: sync.RWMutex{},
	}, nil
}

func (s *Service) ExchangeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrInvalidRequestBody.Error(), http.StatusBadRequest)
		return
	}

	if req.Token == "" {
		http.Error(w, ErrMissingToken.Error(), http.StatusBadRequest)
		return
	}

	orgID := os.Getenv("SNYK_ORG_ID")
	if orgID == "" {
		http.Error(w, ErrMissingOrgID.Error(), http.StatusInternalServerError)
		return
	}

	roleID := os.Getenv("SNYK_ROLE_ID")
	if roleID == "" {
		http.Error(w, ErrMissingRoleID.Error(), http.StatusInternalServerError)
		return
	}

	// Verify the OIDC token
	claims, err := s.verifier.VerifyToken(r.Context(), req.Token)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to verify token: %v", err), http.StatusUnauthorized)
		return
	}

	// Use a generic service account name with the org name
	saName := fmt.Sprintf("github-oidcexchange-%s", claims.RepositoryOwner)

	// Try to get credentials from cache first
	creds, found := s.getCredentialsFromCache(saName)

	if !found {
		// No cache, we need to get or create the service account
		sa, err := s.snyk.GetServiceAccount(r.Context(), orgID, saName)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to get service account: %v", err), http.StatusInternalServerError)
			return
		}

		if sa != nil {
			// Service account exists but not in cache, delete it and recreate
			err = s.snyk.DeleteServiceAccount(r.Context(), orgID, sa.ID)
			if err != nil {
				http.Error(w, fmt.Sprintf("failed to delete old service account: %v", err), http.StatusInternalServerError)
				return
			}
		}

		// Create a new service account
		sa, err = s.snyk.CreateServiceAccount(r.Context(), orgID, saName, "oauth_client_secret", s.roleID)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create service account: %v", err), http.StatusInternalServerError)
			return
		}

		// Cache the new credentials
		creds = ServiceAccountCredentials{
			ID:           sa.ID,
			ClientID:     sa.Attributes.ClientID,
			ClientSecret: sa.Attributes.ClientSecret,
		}
		s.cacheCredentials(saName, creds)
	}

	// Generate access token
	tokenResp, err := s.snyk.CreateToken(r.Context(), creds.ClientID, creds.ClientSecret)
	if err != nil {
		// If token creation fails, the service account might have been deleted or invalidated
		// Remove from cache and try again next time
		s.removeCredentialsFromCache(saName)
		http.Error(w, fmt.Sprintf("failed to create token: %v", err), http.StatusInternalServerError)
		return
	}

	resp := TokenResponse{
		Token: tokenResp.AccessToken,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

// Cache management functions
func (s *Service) getCredentialsFromCache(saName string) (ServiceAccountCredentials, bool) {
	s.cacheMutex.RLock()
	defer s.cacheMutex.RUnlock()

	creds, found := s.credCache[saName]
	return creds, found
}

func (s *Service) cacheCredentials(saName string, creds ServiceAccountCredentials) {
	s.cacheMutex.Lock()
	defer s.cacheMutex.Unlock()

	s.credCache[saName] = creds
}

func (s *Service) removeCredentialsFromCache(saName string) {
	s.cacheMutex.Lock()
	defer s.cacheMutex.Unlock()

	delete(s.credCache, saName)
}
