// Code generated by go-swagger; DO NOT EDIT.

package key_derivation_service_registry

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
)

// NewGetKeyDerivationServiceInstanceParams creates a new GetKeyDerivationServiceInstanceParams object
// with the default values initialized.
func NewGetKeyDerivationServiceInstanceParams() *GetKeyDerivationServiceInstanceParams {
	var ()
	return &GetKeyDerivationServiceInstanceParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetKeyDerivationServiceInstanceParamsWithTimeout creates a new GetKeyDerivationServiceInstanceParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetKeyDerivationServiceInstanceParamsWithTimeout(timeout time.Duration) *GetKeyDerivationServiceInstanceParams {
	var ()
	return &GetKeyDerivationServiceInstanceParams{

		timeout: timeout,
	}
}

// NewGetKeyDerivationServiceInstanceParamsWithContext creates a new GetKeyDerivationServiceInstanceParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetKeyDerivationServiceInstanceParamsWithContext(ctx context.Context) *GetKeyDerivationServiceInstanceParams {
	var ()
	return &GetKeyDerivationServiceInstanceParams{

		Context: ctx,
	}
}

// NewGetKeyDerivationServiceInstanceParamsWithHTTPClient creates a new GetKeyDerivationServiceInstanceParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetKeyDerivationServiceInstanceParamsWithHTTPClient(client *http.Client) *GetKeyDerivationServiceInstanceParams {
	var ()
	return &GetKeyDerivationServiceInstanceParams{
		HTTPClient: client,
	}
}

/*GetKeyDerivationServiceInstanceParams contains all the parameters to send to the API endpoint
for the get key derivation service instance operation typically these are written to a http.Request
*/
type GetKeyDerivationServiceInstanceParams struct {

	/*KeyDerivationInstanceID*/
	KeyDerivationInstanceID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get key derivation service instance params
func (o *GetKeyDerivationServiceInstanceParams) WithTimeout(timeout time.Duration) *GetKeyDerivationServiceInstanceParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get key derivation service instance params
func (o *GetKeyDerivationServiceInstanceParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get key derivation service instance params
func (o *GetKeyDerivationServiceInstanceParams) WithContext(ctx context.Context) *GetKeyDerivationServiceInstanceParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get key derivation service instance params
func (o *GetKeyDerivationServiceInstanceParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get key derivation service instance params
func (o *GetKeyDerivationServiceInstanceParams) WithHTTPClient(client *http.Client) *GetKeyDerivationServiceInstanceParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get key derivation service instance params
func (o *GetKeyDerivationServiceInstanceParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithKeyDerivationInstanceID adds the keyDerivationInstanceID to the get key derivation service instance params
func (o *GetKeyDerivationServiceInstanceParams) WithKeyDerivationInstanceID(keyDerivationInstanceID string) *GetKeyDerivationServiceInstanceParams {
	o.SetKeyDerivationInstanceID(keyDerivationInstanceID)
	return o
}

// SetKeyDerivationInstanceID adds the keyDerivationInstanceId to the get key derivation service instance params
func (o *GetKeyDerivationServiceInstanceParams) SetKeyDerivationInstanceID(keyDerivationInstanceID string) {
	o.KeyDerivationInstanceID = keyDerivationInstanceID
}

// WriteToRequest writes these params to a swagger request
func (o *GetKeyDerivationServiceInstanceParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param keyDerivationInstanceId
	if err := r.SetPathParam("keyDerivationInstanceId", o.KeyDerivationInstanceID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
