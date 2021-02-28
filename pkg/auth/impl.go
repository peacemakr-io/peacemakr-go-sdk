package auth

import (
	"context"
	"errors"
	"time"
	"io/ioutil"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2/clientcredentials"
	jwt "github.com/dgrijalva/jwt-go"
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
		Scopes:         []string{},
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


func (p *PubKeyAuthenticator) GetAuthToken() (string, error) {
	privKeyPath := p.PrivateKeyPath
	keyId := p.KeyId

	signBytes, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return "", err
	}

	var signKey interface{}
	if (p.KeyType[:2] == "ES") {
		signKey, err = jwt.ParseECPrivateKeyFromPEM(signBytes)
		if err != nil {
			return "", err
		}
	} else if (p.KeyType[:2] == "RS") {
		signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
		if err != nil {
			return "", err
		}
	}

	t := jwt.New(jwt.GetSigningMethod(p.KeyType))
	t.Header["kid"] = keyId

	claims := make(jwt.MapClaims)

	// set the expire time
	claims["exp"] = time.Now().Add(p.Expiration).Unix()
	claims["iss"] = "peacemakr.io/keypair"
	claims["aud"] = "https://api.peacemakr.io"
	t.Claims = claims
	tokenString, err := t.SignedString(signKey)
	if err != nil {
		return "", errors.New("Token Signed Error: " + err.Error())
	}

	return tokenString, nil
}
