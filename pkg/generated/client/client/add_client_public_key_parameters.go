// Code generated by go-swagger; DO NOT EDIT.

package client

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"
	"time"

	"golang.org/x/net/context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/peacemakr-io/peacemakr-go-sdk/pkg/generated/models"
)

// NewAddClientPublicKeyParams creates a new AddClientPublicKeyParams object
// with the default values initialized.
func NewAddClientPublicKeyParams() *AddClientPublicKeyParams {
	var ()
	return &AddClientPublicKeyParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewAddClientPublicKeyParamsWithTimeout creates a new AddClientPublicKeyParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewAddClientPublicKeyParamsWithTimeout(timeout time.Duration) *AddClientPublicKeyParams {
	var ()
	return &AddClientPublicKeyParams{

		timeout: timeout,
	}
}

// NewAddClientPublicKeyParamsWithContext creates a new AddClientPublicKeyParams object
// with the default values initialized, and the ability to set a context for a request
func NewAddClientPublicKeyParamsWithContext(ctx context.Context) *AddClientPublicKeyParams {
	var ()
	return &AddClientPublicKeyParams{

		Context: ctx,
	}
}

// NewAddClientPublicKeyParamsWithHTTPClient creates a new AddClientPublicKeyParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewAddClientPublicKeyParamsWithHTTPClient(client *http.Client) *AddClientPublicKeyParams {
	var ()
	return &AddClientPublicKeyParams{
		HTTPClient: client,
	}
}

/*AddClientPublicKeyParams contains all the parameters to send to the API endpoint
for the add client public key operation typically these are written to a http.Request
*/
type AddClientPublicKeyParams struct {

	/*ClientID*/
	ClientID string
	/*NewPublicKey*/
	NewPublicKey *models.PublicKey

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the add client public key params
func (o *AddClientPublicKeyParams) WithTimeout(timeout time.Duration) *AddClientPublicKeyParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the add client public key params
func (o *AddClientPublicKeyParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the add client public key params
func (o *AddClientPublicKeyParams) WithContext(ctx context.Context) *AddClientPublicKeyParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the add client public key params
func (o *AddClientPublicKeyParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the add client public key params
func (o *AddClientPublicKeyParams) WithHTTPClient(client *http.Client) *AddClientPublicKeyParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the add client public key params
func (o *AddClientPublicKeyParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithClientID adds the clientID to the add client public key params
func (o *AddClientPublicKeyParams) WithClientID(clientID string) *AddClientPublicKeyParams {
	o.SetClientID(clientID)
	return o
}

// SetClientID adds the clientId to the add client public key params
func (o *AddClientPublicKeyParams) SetClientID(clientID string) {
	o.ClientID = clientID
}

// WithNewPublicKey adds the newPublicKey to the add client public key params
func (o *AddClientPublicKeyParams) WithNewPublicKey(newPublicKey *models.PublicKey) *AddClientPublicKeyParams {
	o.SetNewPublicKey(newPublicKey)
	return o
}

// SetNewPublicKey adds the newPublicKey to the add client public key params
func (o *AddClientPublicKeyParams) SetNewPublicKey(newPublicKey *models.PublicKey) {
	o.NewPublicKey = newPublicKey
}

// WriteToRequest writes these params to a swagger request
func (o *AddClientPublicKeyParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param clientId
	if err := r.SetPathParam("clientId", o.ClientID); err != nil {
		return err
	}

	if o.NewPublicKey != nil {
		if err := r.SetBodyParam(o.NewPublicKey); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
