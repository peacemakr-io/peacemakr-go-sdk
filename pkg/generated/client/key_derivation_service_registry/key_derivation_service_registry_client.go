// Code generated by go-swagger; DO NOT EDIT.

package key_derivation_service_registry

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"
)

// New creates a new key derivation service registry API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) *Client {
	return &Client{transport: transport, formats: formats}
}

/*
Client for key derivation service registry API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

/*
AddKeyDerivationServiceInstance registers a new key derivation service instance
*/
func (a *Client) AddKeyDerivationServiceInstance(params *AddKeyDerivationServiceInstanceParams, authInfo runtime.ClientAuthInfoWriter) (*AddKeyDerivationServiceInstanceOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewAddKeyDerivationServiceInstanceParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "addKeyDerivationServiceInstance",
		Method:             "POST",
		PathPattern:        "/crypto/deriver/instance",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &AddKeyDerivationServiceInstanceReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*AddKeyDerivationServiceInstanceOK), nil

}

/*
DeleteKeyDerivationServiceInstance activates or deactivate an existing key derivation service instance
*/
func (a *Client) DeleteKeyDerivationServiceInstance(params *DeleteKeyDerivationServiceInstanceParams, authInfo runtime.ClientAuthInfoWriter) (*DeleteKeyDerivationServiceInstanceOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteKeyDerivationServiceInstanceParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "deleteKeyDerivationServiceInstance",
		Method:             "DELETE",
		PathPattern:        "/crypto/deriver/instance/{keyDerivationInstanceId}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &DeleteKeyDerivationServiceInstanceReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*DeleteKeyDerivationServiceInstanceOK), nil

}

/*
GetAllOrgKeyDerivationServiceInstances gets the all key derivers registerd to org
*/
func (a *Client) GetAllOrgKeyDerivationServiceInstances(params *GetAllOrgKeyDerivationServiceInstancesParams, authInfo runtime.ClientAuthInfoWriter) (*GetAllOrgKeyDerivationServiceInstancesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAllOrgKeyDerivationServiceInstancesParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "getAllOrgKeyDerivationServiceInstances",
		Method:             "GET",
		PathPattern:        "/crypto/deriver/all-org-instances",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetAllOrgKeyDerivationServiceInstancesReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*GetAllOrgKeyDerivationServiceInstancesOK), nil

}

/*
GetAllSharedKeyDerivationServiceInstances gets the all key derivers that the org has access to including shared cloud instances
*/
func (a *Client) GetAllSharedKeyDerivationServiceInstances(params *GetAllSharedKeyDerivationServiceInstancesParams, authInfo runtime.ClientAuthInfoWriter) (*GetAllSharedKeyDerivationServiceInstancesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAllSharedKeyDerivationServiceInstancesParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "getAllSharedKeyDerivationServiceInstances",
		Method:             "GET",
		PathPattern:        "/crypto/deriver/all-shared-instances",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetAllSharedKeyDerivationServiceInstancesReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*GetAllSharedKeyDerivationServiceInstancesOK), nil

}

/*
GetKeyDerivationServiceInstance gets the keyderiver details by id
*/
func (a *Client) GetKeyDerivationServiceInstance(params *GetKeyDerivationServiceInstanceParams, authInfo runtime.ClientAuthInfoWriter) (*GetKeyDerivationServiceInstanceOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetKeyDerivationServiceInstanceParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "getKeyDerivationServiceInstance",
		Method:             "GET",
		PathPattern:        "/crypto/deriver/instance/{keyDerivationInstanceId}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetKeyDerivationServiceInstanceReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*GetKeyDerivationServiceInstanceOK), nil

}

/*
HeartbeatKeyDerivationServiceInstance heatbeats from the given key derivation service instance
*/
func (a *Client) HeartbeatKeyDerivationServiceInstance(params *HeartbeatKeyDerivationServiceInstanceParams, authInfo runtime.ClientAuthInfoWriter) (*HeartbeatKeyDerivationServiceInstanceOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewHeartbeatKeyDerivationServiceInstanceParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "heartbeatKeyDerivationServiceInstance",
		Method:             "GET",
		PathPattern:        "/crypto/deriver/instance/{keyDerivationInstanceId}/heartbeat",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &HeartbeatKeyDerivationServiceInstanceReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*HeartbeatKeyDerivationServiceInstanceOK), nil

}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
