package utils

import (
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/peacemakr-io/peacemakr-go-sdk/pkg/auth"
)

type PeacemakrAuthenticator struct {
	auth.Authenticator
}

func (a *PeacemakrAuthenticator) AuthenticateRequest(req runtime.ClientRequest, f strfmt.Registry) error {
	token, err := a.GetAuthToken()
	if err != nil {
		return err
	}
	err = req.SetHeaderParam("Authorization", token)
	return err
}

func GetAuthWriter(auth auth.Authenticator) runtime.ClientAuthInfoWriter {
	a := PeacemakrAuthenticator{
		auth,
	}
	return runtime.ClientAuthInfoWriter(&a)
}
