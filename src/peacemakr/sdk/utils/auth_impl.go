package utils

import (
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

type PeacemakrAuthenticator struct {
	apiKey string
}

func (a *PeacemakrAuthenticator) AuthenticateRequest(req runtime.ClientRequest, f strfmt.Registry) error {
	err := req.SetHeaderParam("Authorization", a.apiKey)
	return err
}

func GetAuthWriter(apiKey string) runtime.ClientAuthInfoWriter {
	auth := PeacemakrAuthenticator{
		apiKey: apiKey,
	}
	return runtime.ClientAuthInfoWriter(&auth)
}
