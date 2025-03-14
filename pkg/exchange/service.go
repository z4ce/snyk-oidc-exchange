package exchange

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

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

type Service struct {
	verifier *oidc.Verifier
	snyk     *snyk.Client
	roleID   string
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
		verifier: verifier,
		snyk:     snyk.NewClient(snykToken),
		roleID:   roleID,
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

	// Create or get service account
	saName := fmt.Sprintf("github-%s", claims.Repository)
	sa, err := s.snyk.GetServiceAccount(r.Context(), orgID, saName)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get service account: %v", err), http.StatusInternalServerError)
		return
	}

	if sa == nil {
		sa, err = s.snyk.CreateServiceAccount(r.Context(), orgID, saName, "api_key", s.roleID)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create service account: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Generate access token
	token, err := s.snyk.CreateToken(r.Context(), orgID, sa.ID)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create token: %v", err), http.StatusInternalServerError)
		return
	}

	resp := TokenResponse{
		Token: token,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}
