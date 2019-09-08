// Code generated by go-swagger; DO NOT EDIT.

package client

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"
)

// New creates a new client API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) *Client {
	return &Client{transport: transport, formats: formats}
}

/*
Client for client API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

/*
AddClient registers a new client
*/
func (a *Client) AddClient(params *AddClientParams, authInfo runtime.ClientAuthInfoWriter) (*AddClientOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewAddClientParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "addClient",
		Method:             "POST",
		PathPattern:        "/client",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &AddClientReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*AddClientOK), nil

}

/*
AddClientPublicKey registers a new public key for the client
*/
func (a *Client) AddClientPublicKey(params *AddClientPublicKeyParams, authInfo runtime.ClientAuthInfoWriter) (*AddClientPublicKeyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewAddClientPublicKeyParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "addClientPublicKey",
		Method:             "POST",
		PathPattern:        "/client/{clientId}/addPublicKey",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &AddClientPublicKeyReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*AddClientPublicKeyOK), nil

}

/*
DeleteClient removes an existing organization
*/
func (a *Client) DeleteClient(params *DeleteClientParams, authInfo runtime.ClientAuthInfoWriter) (*DeleteClientOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteClientParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "deleteClient",
		Method:             "DELETE",
		PathPattern:        "/client/{clientId}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &DeleteClientReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*DeleteClientOK), nil

}

/*
GetClient gets an existing client
*/
func (a *Client) GetClient(params *GetClientParams, authInfo runtime.ClientAuthInfoWriter) (*GetClientOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetClientParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "getClient",
		Method:             "GET",
		PathPattern:        "/client/{clientId}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetClientReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*GetClientOK), nil

}

/*
ReturnPagedClientIds returns a page of client ids that belong to the authenticated org
*/
func (a *Client) ReturnPagedClientIds(params *ReturnPagedClientIdsParams, authInfo runtime.ClientAuthInfoWriter) (*ReturnPagedClientIdsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewReturnPagedClientIdsParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "returnPagedClientIds",
		Method:             "GET",
		PathPattern:        "/client",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &ReturnPagedClientIdsReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*ReturnPagedClientIdsOK), nil

}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
