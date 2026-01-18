package workloadidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	EmptyGuid = "00000000-0000-0000-0000-000000000000" //nolint:revive //FIXME(var-naming)
)

type Token struct {
	AccessToken string
	ExpiresOn   time.Time
}

type TokenProvider interface {
	GetToken(scope string) (*Token, error)
}

// Used to propagate initialization error if any
var initError error

func CalculateCacheExpiryBasedOnTokenExpiry(tokenExpiry time.Time) time.Duration {
	// Calculate the cache expiry as 5 minutes before the token expires
	cacheExpiry := time.Until(tokenExpiry) - time.Minute*5
	return cacheExpiry
}

type gcpTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}


func GetGCPWorkloadIdentityToken(ctx context.Context) (Token, error) {
	// Fetch token from the metadata server
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return Token{}, fmt.Errorf("failed to create request to metadata server: %w", err)
	}
	req.Header.Add("Metadata-Flavor", "Google")

		client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return Token{}, fmt.Errorf("failed to get token from metadata server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Token{}, fmt.Errorf("metadata server returned non-200 status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Token{}, fmt.Errorf("failed to read response body from metadata server: %w", err)
	}
	var tr gcpTokenResponse
	err = json.Unmarshal(body, &tr)
	if err != nil {
		return Token{}, fmt.Errorf("failed to unmarshal token response: %w", err)
	}

	tokenExpiry := time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return Token{
		AccessToken: tr.AccessToken,
		ExpiresOn:   tokenExpiry,
	}, nil
}