// Code generated by go-swagger; DO NOT EDIT.

package login

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"
)

// New creates a new login API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) *Client {
	return &Client{transport: transport, formats: formats}
}

/*
Client for login API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

/*
Login afters aquiring and o auth2 open Id id token from Id p like google login present it here and proceed with the required flow if this is a new user they ll have to create an org else they will just get their org details and an API key associated with their org
*/
func (a *Client) Login(params *LoginParams) (*LoginOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewLoginParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "login",
		Method:             "GET",
		PathPattern:        "/login",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &LoginReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*LoginOK), nil

}

/*
LoginInviteUser invites bind an existing user that is not already bound to an org to your org
*/
func (a *Client) LoginInviteUser(params *LoginInviteUserParams, authInfo runtime.ClientAuthInfoWriter) (*LoginInviteUserOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewLoginInviteUserParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "loginInviteUser",
		Method:             "POST",
		PathPattern:        "/login/inviteUser",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &LoginInviteUserReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*LoginInviteUserOK), nil

}

/*
LoginUninviteUser uninvites remove an existing user that is part of your org
*/
func (a *Client) LoginUninviteUser(params *LoginUninviteUserParams, authInfo runtime.ClientAuthInfoWriter) (*LoginUninviteUserOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewLoginUninviteUserParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "loginUninviteUser",
		Method:             "DELETE",
		PathPattern:        "/login/inviteUser",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &LoginUninviteUserReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*LoginUninviteUserOK), nil

}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}