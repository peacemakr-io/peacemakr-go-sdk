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

	models "github.com/peacemakr-io/peacemakr-go-sdk/generated/models"
)

// NewAddKeyDerivationServiceInstanceParams creates a new AddKeyDerivationServiceInstanceParams object
// with the default values initialized.
func NewAddKeyDerivationServiceInstanceParams() *AddKeyDerivationServiceInstanceParams {
	var ()
	return &AddKeyDerivationServiceInstanceParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewAddKeyDerivationServiceInstanceParamsWithTimeout creates a new AddKeyDerivationServiceInstanceParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewAddKeyDerivationServiceInstanceParamsWithTimeout(timeout time.Duration) *AddKeyDerivationServiceInstanceParams {
	var ()
	return &AddKeyDerivationServiceInstanceParams{

		timeout: timeout,
	}
}

// NewAddKeyDerivationServiceInstanceParamsWithContext creates a new AddKeyDerivationServiceInstanceParams object
// with the default values initialized, and the ability to set a context for a request
func NewAddKeyDerivationServiceInstanceParamsWithContext(ctx context.Context) *AddKeyDerivationServiceInstanceParams {
	var ()
	return &AddKeyDerivationServiceInstanceParams{

		Context: ctx,
	}
}

// NewAddKeyDerivationServiceInstanceParamsWithHTTPClient creates a new AddKeyDerivationServiceInstanceParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewAddKeyDerivationServiceInstanceParamsWithHTTPClient(client *http.Client) *AddKeyDerivationServiceInstanceParams {
	var ()
	return &AddKeyDerivationServiceInstanceParams{
		HTTPClient: client,
	}
}

/*AddKeyDerivationServiceInstanceParams contains all the parameters to send to the API endpoint
for the add key derivation service instance operation typically these are written to a http.Request
*/
type AddKeyDerivationServiceInstanceParams struct {

	/*KeyDerivationInstance*/
	KeyDerivationInstance *models.KeyDerivationInstance

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the add key derivation service instance params
func (o *AddKeyDerivationServiceInstanceParams) WithTimeout(timeout time.Duration) *AddKeyDerivationServiceInstanceParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the add key derivation service instance params
func (o *AddKeyDerivationServiceInstanceParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the add key derivation service instance params
func (o *AddKeyDerivationServiceInstanceParams) WithContext(ctx context.Context) *AddKeyDerivationServiceInstanceParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the add key derivation service instance params
func (o *AddKeyDerivationServiceInstanceParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the add key derivation service instance params
func (o *AddKeyDerivationServiceInstanceParams) WithHTTPClient(client *http.Client) *AddKeyDerivationServiceInstanceParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the add key derivation service instance params
func (o *AddKeyDerivationServiceInstanceParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithKeyDerivationInstance adds the keyDerivationInstance to the add key derivation service instance params
func (o *AddKeyDerivationServiceInstanceParams) WithKeyDerivationInstance(keyDerivationInstance *models.KeyDerivationInstance) *AddKeyDerivationServiceInstanceParams {
	o.SetKeyDerivationInstance(keyDerivationInstance)
	return o
}

// SetKeyDerivationInstance adds the keyDerivationInstance to the add key derivation service instance params
func (o *AddKeyDerivationServiceInstanceParams) SetKeyDerivationInstance(keyDerivationInstance *models.KeyDerivationInstance) {
	o.KeyDerivationInstance = keyDerivationInstance
}

// WriteToRequest writes these params to a swagger request
func (o *AddKeyDerivationServiceInstanceParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.KeyDerivationInstance != nil {
		if err := r.SetBodyParam(o.KeyDerivationInstance); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
