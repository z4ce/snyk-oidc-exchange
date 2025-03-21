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

## General Flow
- Set up a Snyk user account with privileges allowing it to create a ServiceAccount for your chosen Snyk org
- Deploy this service in an environment you control, which can be accessed from your GitHub account and which can access Snyk
- Deploy a GitHub Action which calls this service to exchange a GitHub OIDC token for a Snyk one

# Set up Snyk user account
## Retrieve the ID of the Member Role which will be assigned to the service account
Group > Settings > Member Roles - click on the role you wish to assign
Save the ID - this will be assigned to the environment variable SNYK_ROLE_ID

## Retrieve the ID of the Org you want to use
Org > Settings > General - Organization ID
Save the ID - this will be assigned to the environment variable SNYK_ORG_ID

## Create a Service Account as OrgAdmin in the Organization
Org > Settings > Service Accounts
Create an account with Service account type = API Key
Save the API Key - this will be assigned to the environment variable SNYK_TOKEN



# Service Deployment
## Prerequisites
- Runtime environment with internet access
- Go 1.23 or later

## Environment Variables

- `SNYK_TOKEN`: Snyk API token with sufficient privileges to make new service accounts
- `SNYK_ORG_ID`: The ID of your Snyk organization that a new restricted service account will be created in
- `SNYK_ROLE_ID`: The role of the restricted user account
- `ALLOWED_OWNER`: The GitHub organization/owner that is allowed to exchange tokens
- `PORT`: (Optional) The port to run the server on (default: 8080)

## Installation

```bash
go get github.com/z4ce/snyk-oidc-exchange
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


# Example GitHub Action Using Service
## Prerequisites 
### Define two repository variables:
  In your GitHub account go to
  Settings / Secrets and Variables / Variables
  New repository variable

- `OIDC_EXCHANGE_URL`: The full URL where this service is running e.g. http://my.oidc-exchange.mydomain.com:8080/exchange
- `SNYK_ORG_ID`: The ID of the Snyk organization where your Target lives

## Action Definition
```yaml
name: Run Snyk Test

on:
  workflow_dispatch: # Allows manual trigger of the workflow
permissions:
  id-token: write # This is required for requesting the JWT
  contents: read
jobs:
  print-token:
    
    runs-on: ubuntu-latest
    
    steps:
      - name: Request Snyk Token
        run: |
               RESPONSE=$(curl -X POST "${{ vars.OIDC_EXCHANGE_URL }}" \
               -H "Content-Type: application/json" \
               -d '{"token": "'$ACTIONS_ID_TOKEN_REQUEST_TOKEN'"}')
               SNYK_TOKEN=$(echo $RESPONSE | jq -r .token)
               echo "SNYK_OAUTH_TOKEN=$SNYK_TOKEN" >> $GITHUB_ENV

      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: setup jdk 8
        uses: actions/setup-java@v4
        with:
          distribution: 'zulu'
          java-version: 8
          server-id: github # Value of the distributionManagement/repository/id field of the pom.xml
          settings-path: ${{ github.workspace }} # location for the settings.xml file

      - name: unit tests
        run: mvn -B test --file pom.xml

      - name: build the app
        run: |
          mvn clean
          mvn -B package --file pom.xml
          
      - name: Set up Snyk CLI to check for security issues
        # Snyk can be used to break the build when it detects security issues.
        # In this case we want to upload the SAST issues to GitHub Code Scanning
        uses: snyk/actions/setup@master

        # Runs Snyk OSS analysis and upload the results
      - name: Run snyk test
        run: snyk monitor --debug --org=${{ vars.SNYK_ORG_ID }}
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

