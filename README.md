# Snyk OIDC Token Exchange Service

This service enables secure token exchange between GitHub Actions OIDC tokens and Snyk service account tokens. It verifies the GitHub OIDC token and creates a temporary Snyk service account token with a 10-minute TTL.

## Features

- Verifies GitHub Actions OIDC tokens
- Creates Snyk service accounts if they don't exist
- Generates temporary Snyk tokens with 10-minute TTL
- Secure token exchange with proper validation

## Prerequisites

- Go 1.23 or later
- A Snyk account with admin access to create service accounts
- GitHub Actions workflow with OIDC enabled

## Environment Variables

- `SNYK_TOKEN`: Your Snyk API token with admin privileges
- `SNYK_ORG_ID`: The ID of your Snyk organization
- `ALLOWED_OWNER`: The GitHub organization/owner that is allowed to exchange tokens
- `PORT`: (Optional) The port to run the server on (default: 8080)

## Installation

```bash
go get z4ce.com/snyk-oidc-exchange
```

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

## License

MIT 