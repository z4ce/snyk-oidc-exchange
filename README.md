# Snyk OIDC Token Exchange Service

This service enables secure token exchange between GitHub Actions OIDC tokens and Snyk service account tokens. It verifies the GitHub OIDC token and creates a temporary Snyk service account token with a 10-minute TTL.

## Features

- Verifies GitHub Actions OIDC tokens
- Creates Snyk service accounts if they don't exist
- Generates temporary Snyk tokens with 10-minute TTL
- Secure token exchange with proper validationgit co

# Example GitHub Action Using Service

```yaml
name: Run Snyk Test

on:
  workflow_dispatch: # Allows manual trigger of the workflow
permissions:
  id-token: write # This is required for requesting the JWT
  contents: read  # This is required for actions/checkout
jobs:
  print-token:
    runs-on: ubuntu-latest
    steps:
      - name: Request Snyk Token
        run: |
               TOKEN=$(curl -X POST https://snyk-oidc-exchange.company.com/exchange \
               -H "Content-Type: application/json" \
               -d '{"token": "'$ACTIONS_ID_TOKEN_REQUEST_TOKEN'"}' | jq -r .token)
               echo "SNYK_OAUTH_TOKEN=$TOKEN" >> $GITHUB_ENV
      - uses: snyk/actions/setup@master
      - uses: actions/checkout@v3
      - name: Run snyk test
        run: snyk test
```

## Prerequisites

- Go 1.23 or later
- A Snyk account with admin access to create service accounts
- GitHub Actions workflow with OIDC enabled

## Environment Variables

- `SNYK_TOKEN`: Snyk API token with sufficient privileges to make new service accounts
- `SNYK_ORG_ID`: The ID of your Snyk organization that a new restricted service account will be created in
- `SNYK_ROLE_ID`: The role of the restricted user account
- `ALLOWED_OWNER`: The GitHub organization/owner that is allowed to exchange tokens
- `PORT`: (Optional) The port to run the server on (default: 8080)

## Installation

Download the latest release from the GitHub releases page for your architecture.

## Usage

1. Start the service:

```bash
export SNYK_TOKEN=your-snyk-token
export SNYK_ORG_ID=your-org-id
export ALLOWED_OWNER=your-github-org
go run cmd/exchange-token/main.go
```

2. Exchange a token:

```bash
curl -X POST http://localhost:8080/exchange \
  -H "Content-Type: application/json" \
  -d '{"token": "your-github-oidc-token"}'
```

The service will respond with a Snyk token:

```json
{
  "token": "your-temporary-snyk-token"
}
```

## API

### POST /exchange

Exchanges a GitHub Actions OIDC token for a temporary Snyk token.

**Request Body:**
```json
{
  "token": "github-oidc-token"
}
```

**Response:**
```json
{
  "token": "snyk-token"
}
```

**Error Responses:**
- 400 Bad Request: Invalid request body or missing token
- 401 Unauthorized: Invalid OIDC token
- 500 Internal Server Error: Server-side errors

## Security

- The service verifies the GitHub OIDC token's signature and claims
- Only allows tokens from the configured GitHub organization
- Creates unique service accounts per repository
- Generates short-lived tokens (10 minutes)
- Requires secure environment variables

## Releasing

This project uses [GoReleaser](https://goreleaser.com/) for automated releases through GitHub Actions.

### Release Process

1. Create and push a new tag:
   ```bash
   git tag -a v0.1.0 -m "First release"
   git push origin v0.1.0
   ```

2. The GitHub Action will automatically:
   - Build binaries for multiple platforms (Linux, macOS, Windows)
   - Create GitHub release with release notes and binaries
   - Build and push Docker images to GitHub Container Registry (GHCR)

### Docker Images

Docker images are available from GitHub Container Registry:

```bash
# Pull the latest image
docker pull ghcr.io/OWNER/snyk-oidc-exchange:latest

# Run the container
docker run -p 8080:8080 \
  -e SNYK_TOKEN=your-token \
  -e SNYK_ORG_ID=your-org-id \
  -e ALLOWED_OWNER=your-github-org \
  ghcr.io/OWNER/snyk-oidc-exchange:latest
```

Where `OWNER` is your GitHub username or organization.

