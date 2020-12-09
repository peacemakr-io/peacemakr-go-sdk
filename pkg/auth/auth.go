package auth

// This must be provided to get the token to be used for API authentication. This can be an API key
// or an OpenID Connect token.
type Authenticator interface {
	GetAuthToken() (string, error)
}

// Provides an Authenticator for use with an API key
type APIKeyAuthenticator struct {
	Key string
}

// Gets a secret token from storage - could be a function that returns a constant string or it could
// perform a network call to fetch a secret from a secret manager.
type SecretFetcher func() (string, error)

type OIDCAuthenticator struct {
	Issuer         string
	ClientID       string
	Secret         SecretFetcher
	PeacemakrOrgID string
}

func GetOIDCAuthenticator(issuer, clientId string, secret SecretFetcher, orgId string) Authenticator {
	return &OIDCAuthenticator{
		Issuer:         issuer,
		ClientID:       clientId,
		Secret:         secret,
		PeacemakrOrgID: orgId,
	}
}
