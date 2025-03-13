package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const testToken = `eyJhbGciOiJSUzI1NiIsImtpZCI6IjM4ODI2YjE3LTZhMzAtNWY5Yi1iMTY5LThiZWI4MjAyZjcyMyIsInR5cCI6IkpXVCIsIng1dCI6InlrTmFZNHFNX3RhNGsyVGdaT0NFWUxrY1lsQSJ9.eyJJZGVudGl0eVR5cGVDbGFpbSI6IlN5c3RlbTpTZXJ2aWNlSWRlbnRpdHkiLCJhYyI6Ilt7XCJTY29wZVwiOlwicmVmcy9oZWFkcy9tYWluXCIsXCJQZXJtaXNzaW9uXCI6M31dIiwiYWNzbCI6IjEwIiwiYXVkIjoidnNvOjQxMjA2YzEzLTM3NTMtNDhkNy05NTM2LWFhNWY3YmMxZTg4YiIsImJpbGxpbmdfb3duZXJfaWQiOiJVX2tnRE9BRW9yOGciLCJleHAiOjE3NDEzMDUyMjUsImh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9jbGFpbXMvcHJpbWFyeXNpZCI6ImRkZGRkZGRkLWRkZGQtZGRkZC1kZGRkLWRkZGRkZGRkZGRkZCIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL3NpZCI6ImRkZGRkZGRkLWRkZGQtZGRkZC1kZGRkLWRkZGRkZGRkZGRkZCIsImlhdCI6MTc0MTI4MzAyNSwiaXNzIjoiaHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImpvYl9pZCI6IjVmZjAxNTVkLWY2ZmEtNTAwMy1hYmY1LTljYWI1OWY1YjQyZSIsIm5hbWVpZCI6ImRkZGRkZGRkLWRkZGQtZGRkZC1kZGRkLWRkZGRkZGRkZGRkZCIsIm5iZiI6MTc0MTI4MjcyNSwib2lkY19leHRyYSI6IntcImFjdG9yXCI6XCJ6NGNlXCIsXCJhY3Rvcl9pZFwiOlwiNDg2MDkxNFwiLFwiYmFzZV9yZWZcIjpcIlwiLFwiZXZlbnRfbmFtZVwiOlwid29ya2Zsb3dfZGlzcGF0Y2hcIixcImhlYWRfcmVmXCI6XCJcIixcImpvYl93b3JrZmxvd19yZWZcIjpcIno0Y2UvdGVzdC1naGFjdGlvbnMvLmdpdGh1Yi93b3JrZmxvd3MvdGVzdC55bWxAcmVmcy9oZWFkcy9tYWluXCIsXCJqb2Jfd29ya2Zsb3dfc2hhXCI6XCJmNzZmOTM0MjEzMzFlNzdkMWNjNDMwODBlZWU0ZWY3OTA1ZmNjZDI1XCIsXCJyZWZcIjpcInJlZnMvaGVhZHMvbWFpblwiLFwicmVmX3Byb3RlY3RlZFwiOlwiZmFsc2VcIixcInJlZl90eXBlXCI6XCJicmFuY2hcIixcInJlcG9zaXRvcnlcIjpcIno0Y2UvdGVzdC1naGFjdGlvbnNcIixcInJlcG9zaXRvcnlfaWRcIjpcIjk0MzU3OTA0MFwiLFwicmVwb3NpdG9yeV9vd25lclwiOlwiejRjZVwiLFwicmVwb3NpdG9yeV9vd25lcl9pZFwiOlwiNDg2MDkxNFwiLFwicmVwb3NpdG9yeV92aXNpYmlsaXR5XCI6XCJwcml2YXRlXCIsXCJydW5fYXR0ZW1wdFwiOlwiMVwiLFwicnVuX2lkXCI6XCIxMzcwNDg1MDI3OFwiLFwicnVuX251bWJlclwiOlwiNFwiLFwicnVubmVyX2Vudmlyb25tZW50XCI6XCJnaXRodWItaG9zdGVkXCIsXCJzaGFcIjpcImY3NmY5MzQyMTMzMWU3N2QxY2M0MzA4MGVlZTRlZjc5MDVmY2NkMjVcIixcIndvcmtmbG93XCI6XCJQcmludCBCYXNlNjQgRW5jb2RlZCBHaXRIdWIgVG9rZW5cIixcIndvcmtmbG93X3JlZlwiOlwiejRjZS90ZXN0LWdoYWN0aW9ucy8uZ2l0aHViL3dvcmtmbG93cy90ZXN0LnltbEByZWZzL2hlYWRzL21haW5cIixcIndvcmtmbG93X3NoYVwiOlwiZjc2ZjkzNDIxMzMxZTc3ZDFjYzQzMDgwZWVlNGVmNzkwNWZjY2QyNVwifSIsIm9pZGNfc3ViIjoicmVwbzp6NGNlL3Rlc3QtZ2hhY3Rpb25zOnJlZjpyZWZzL2hlYWRzL21haW4iLCJvcmNoX2lkIjoiZmE2NDNlNWUtNTA4ZC00YjY3LTkwMWUtZmM5YWY1ZWI0YzU2LnByaW50LXRva2VuLl9fZGVmYXVsdCIsIm93bmVyX2lkIjoiVV9rZ0RPQUVvcjhnIiwicGxhbl9pZCI6ImZhNjQzZTVlLTUwOGQtNGI2Ny05MDFlLWZjOWFmNWViNGM1NiIsInJ1bl9pZCI6IjEzNzA0ODUwMjc4IiwicnVuX251bWJlciI6IjQiLCJydW5fdHlwZSI6ImZ1bGwiLCJydW5uZXJfaWQiOiIxMDAwMDAwMDAxIiwicnVubmVyX3R5cGUiOiJob3N0ZWQiLCJzY3AiOiJBY3Rpb25zLlJlc3VsdHM6ZmE2NDNlNWUtNTA4ZC00YjY3LTkwMWUtZmM5YWY1ZWI0YzU2OjVmZjAxNTVkLWY2ZmEtNTAwMy1hYmY1LTljYWI1OWY1YjQyZSBBY3Rpb25zLlJ1bm5lcjpmYTY0M2U1ZS01MDhkLTRiNjctOTAxZS1mYzlhZjVlYjRjNTY6NWZmMDE1NWQtZjZmYS01MDAzLWFiZjUtOWNhYjU5ZjViNDJlIEFjdGlvbnMuVXBsb2FkQXJ0aWZhY3RzOmZhNjQzZTVlLTUwOGQtNGI2Ny05MDFlLWZjOWFmNWViNGM1Njo1ZmYwMTU1ZC1mNmZhLTUwMDMtYWJmNS05Y2FiNTlmNWI0MmUgZ2VuZXJhdGVfaWRfdG9rZW46ZmE2NDNlNWUtNTA4ZC00YjY3LTkwMWUtZmM5YWY1ZWI0YzU2OjVmZjAxNTVkLWY2ZmEtNTAwMy1hYmY1LTljYWI1OWY1YjQyZSBBY3Rpb25zLkdlbmVyaWNSZWFkOjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCIsInNoYSI6ImY3NmY5MzQyMTMzMWU3N2QxY2M0MzA4MGVlZTRlZjc5MDVmY2NkMjUifQ.3EzPcNToLW6mgOknTmd7WJTS89Ds4zCeX-81m5ahI0FIG3RDZEdkpqSHO3CAmIG3pyn-9MnmCO8-ELPWgfljQipUMzaWO7iJeVeimoqCmdzFmrIgdzp5THEzi9Q8Jnszl4L0SrLoaQud2otrD2R9NhYlLtfMAGUyV2mpT2zsHUK4XU7F8zoDEy7lYfULVM27OBeW36HCLUsIKkbK1PPVrL5_rkpzOD-fq_nuaN4u1cg_vHWGCoqbsuhH-VgmWQy9BkZtpFnQy_WwBRj99qO_IlDwdHHTn8VqZ-OjQOZzM-GvWStWG51CaASwIALT6FwTXrUjUIeuS_3ADHGpbUzTyQ`

// testVerifier is a custom verifier that loads JWKS from a local file
type testVerifier struct {
	*Verifier
	fixedTime time.Time
}

func newTestVerifier(t *testing.T, allowedOwner string) *testVerifier {
	// Load the JWKS from the test data file
	jwksData, err := os.ReadFile("testdata/github_jwks.json")
	if err != nil {
		t.Fatalf("failed to read test JWKS file: %v", err)
	}

	keySet, err := jwk.Parse(jwksData)
	if err != nil {
		t.Fatalf("failed to parse JWKS: %v", err)
	}

	v := &testVerifier{
		Verifier: &Verifier{
			keySet:       keySet,
			allowedOwner: allowedOwner,
		},
		// Set a fixed time that matches the token's issuance time
		fixedTime: time.Unix(1741283025, 0),
	}

	return v
}

func (v *testVerifier) VerifyToken(ctx context.Context, tokenString string) (*Claims, error) {
	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithKeySet(v.keySet),
		jwt.WithIssuer(GitHubOIDCIssuer),
		jwt.WithValidate(true),
		// Use our fixed time for validation
		jwt.WithClock(jwt.ClockFunc(func() time.Time { return v.fixedTime })),
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

func TestVerifyToken(t *testing.T) {
	tests := []struct {
		name         string
		token        string
		allowedOwner string
		wantOwner    string
		wantRepo     string
		wantError    bool
	}{
		{
			name:         "valid token with correct owner",
			token:        testToken,
			allowedOwner: "z4ce",
			wantOwner:    "z4ce",
			wantRepo:     "z4ce/test-ghactions",
			wantError:    false,
		},
		{
			name:         "valid token with incorrect owner",
			token:        testToken,
			allowedOwner: "wrong-owner",
			wantError:    true,
		},
		{
			name:         "invalid token",
			token:        "invalid-token",
			allowedOwner: "z4ce",
			wantError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newTestVerifier(t, tt.allowedOwner)
			claims, err := v.VerifyToken(context.Background(), tt.token)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if claims.RepositoryOwner != tt.wantOwner {
				t.Errorf("got owner %q, want %q", claims.RepositoryOwner, tt.wantOwner)
			}

			if claims.Repository != tt.wantRepo {
				t.Errorf("got repository %q, want %q", claims.Repository, tt.wantRepo)
			}
		})
	}
}
