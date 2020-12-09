package auth

import (
	"context"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2/clientcredentials"
)

func (a *APIKeyAuthenticator) GetAuthToken() (string, error) {
	return a.Key, nil
}

func (a *OIDCAuthenticator) GetAuthToken() (string, error) {
	ctx := context.Background()
	// Create a new provider
	provider, err := oidc.NewProvider(ctx, a.Issuer)
	if err != nil {
		return "", err
	}

	// Get the endpoint
	endpoint := provider.Endpoint()
	// Get the client secret
	secret, err := a.Secret()
	if err != nil {
		return "", err
	}
	// Setup the oauth config
	cfg := clientcredentials.Config{
		ClientID:       a.ClientID,
		ClientSecret:   secret,
		TokenURL:       endpoint.TokenURL,
		Scopes:         []string{"openid", "email"},
		EndpointParams: nil,
		AuthStyle:      endpoint.AuthStyle,
	}
	// Pull down a token
	token, err := cfg.Token(ctx)
	if err != nil {
		return "", err
	}

	// Return the access token
	return token.AccessToken, nil
}
