package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	// GitHubOIDCIssuer is the issuer URL for GitHub Actions OIDC tokens
	GitHubOIDCIssuer = "https://token.actions.githubusercontent.com"
	// GitHubJWKSEndpoint is the endpoint for GitHub's JWKS
	GitHubJWKSEndpoint = "https://token.actions.githubusercontent.com/.well-known/jwks"
)

// Claims represents the custom claims we expect in the GitHub Actions OIDC token
type Claims struct {
	Repository           string `json:"repository"`
	RepositoryOwner      string `json:"repository_owner"`
	WorkflowRef          string `json:"workflow_ref"`
	RepositoryVisibility string `json:"repository_visibility"`
}

// Verifier handles verification of GitHub Actions OIDC tokens
type Verifier struct {
	keySet       jwk.Set
	allowedOwner string
}

// NewVerifier creates a new Verifier instance
func NewVerifier(ctx context.Context, allowedOwner string) (*Verifier, error) {
	keySet, err := jwk.Fetch(ctx, GitHubJWKSEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	return &Verifier{
		keySet:       keySet,
		allowedOwner: allowedOwner,
	}, nil
}

// VerifyToken verifies the GitHub Actions OIDC token and checks the repository owner
func (v *Verifier) VerifyToken(ctx context.Context, tokenString string) (*Claims, error) {
	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithKeySet(v.keySet),
		jwt.WithIssuer(GitHubOIDCIssuer),
		jwt.WithValidate(true),
		jwt.WithClock(jwt.ClockFunc(func() time.Time { return time.Now() })),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and verify token: %w", err)
	}

	// Get the oidc_extra field which contains the repository information
	oidcExtra, ok := token.PrivateClaims()["oidc_extra"].(string)
	if !ok {
		return nil, fmt.Errorf("oidc_extra claim not found or invalid")
	}

	var extraClaims struct {
		Repository           string `json:"repository"`
		RepositoryOwner      string `json:"repository_owner"`
		WorkflowRef          string `json:"workflow_ref"`
		RepositoryVisibility string `json:"repository_visibility"`
	}

	if err := json.Unmarshal([]byte(oidcExtra), &extraClaims); err != nil {
		return nil, fmt.Errorf("failed to parse oidc_extra: %w", err)
	}

	// Verify repository owner matches allowed owner
	if extraClaims.RepositoryOwner != v.allowedOwner {
		return nil, fmt.Errorf("repository owner %q is not allowed (expected: %q)", extraClaims.RepositoryOwner, v.allowedOwner)
	}

	claims := &Claims{
		Repository:           extraClaims.Repository,
		RepositoryOwner:      extraClaims.RepositoryOwner,
		WorkflowRef:          extraClaims.WorkflowRef,
		RepositoryVisibility: extraClaims.RepositoryVisibility,
	}

	return claims, nil
}
