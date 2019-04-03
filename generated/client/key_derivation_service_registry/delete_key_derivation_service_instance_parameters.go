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

// NewDeleteKeyDerivationServiceInstanceParams creates a new DeleteKeyDerivationServiceInstanceParams object
// with the default values initialized.
func NewDeleteKeyDerivationServiceInstanceParams() *DeleteKeyDerivationServiceInstanceParams {
	var ()
	return &DeleteKeyDerivationServiceInstanceParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteKeyDerivationServiceInstanceParamsWithTimeout creates a new DeleteKeyDerivationServiceInstanceParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewDeleteKeyDerivationServiceInstanceParamsWithTimeout(timeout time.Duration) *DeleteKeyDerivationServiceInstanceParams {
	var ()
	return &DeleteKeyDerivationServiceInstanceParams{

		timeout: timeout,
	}
}

// NewDeleteKeyDerivationServiceInstanceParamsWithContext creates a new DeleteKeyDerivationServiceInstanceParams object
// with the default values initialized, and the ability to set a context for a request
func NewDeleteKeyDerivationServiceInstanceParamsWithContext(ctx context.Context) *DeleteKeyDerivationServiceInstanceParams {
	var ()
	return &DeleteKeyDerivationServiceInstanceParams{

		Context: ctx,
	}
}

// NewDeleteKeyDerivationServiceInstanceParamsWithHTTPClient creates a new DeleteKeyDerivationServiceInstanceParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewDeleteKeyDerivationServiceInstanceParamsWithHTTPClient(client *http.Client) *DeleteKeyDerivationServiceInstanceParams {
	var ()
	return &DeleteKeyDerivationServiceInstanceParams{
		HTTPClient: client,
	}
}

/*DeleteKeyDerivationServiceInstanceParams contains all the parameters to send to the API endpoint
for the delete key derivation service instance operation typically these are written to a http.Request
*/
type DeleteKeyDerivationServiceInstanceParams struct {

	/*Active*/
	Active string
	/*KeyDerivationInstanceID*/
	KeyDerivationInstanceID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the delete key derivation service instance params
func (o *DeleteKeyDerivationServiceInstanceParams) WithTimeout(timeout time.Duration) *DeleteKeyDerivationServiceInstanceParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete key derivation service instance params
func (o *DeleteKeyDerivationServiceInstanceParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete key derivation service instance params
func (o *DeleteKeyDerivationServiceInstanceParams) WithContext(ctx context.Context) *DeleteKeyDerivationServiceInstanceParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete key derivation service instance params
func (o *DeleteKeyDerivationServiceInstanceParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete key derivation service instance params
func (o *DeleteKeyDerivationServiceInstanceParams) WithHTTPClient(client *http.Client) *DeleteKeyDerivationServiceInstanceParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete key derivation service instance params
func (o *DeleteKeyDerivationServiceInstanceParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithActive adds the active to the delete key derivation service instance params
func (o *DeleteKeyDerivationServiceInstanceParams) WithActive(active string) *DeleteKeyDerivationServiceInstanceParams {
	o.SetActive(active)
	return o
}

// SetActive adds the active to the delete key derivation service instance params
func (o *DeleteKeyDerivationServiceInstanceParams) SetActive(active string) {
	o.Active = active
}

// WithKeyDerivationInstanceID adds the keyDerivationInstanceID to the delete key derivation service instance params
func (o *DeleteKeyDerivationServiceInstanceParams) WithKeyDerivationInstanceID(keyDerivationInstanceID string) *DeleteKeyDerivationServiceInstanceParams {
	o.SetKeyDerivationInstanceID(keyDerivationInstanceID)
	return o
}

// SetKeyDerivationInstanceID adds the keyDerivationInstanceId to the delete key derivation service instance params
func (o *DeleteKeyDerivationServiceInstanceParams) SetKeyDerivationInstanceID(keyDerivationInstanceID string) {
	o.KeyDerivationInstanceID = keyDerivationInstanceID
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteKeyDerivationServiceInstanceParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param active
	qrActive := o.Active
	qActive := qrActive
	if qActive != "" {
		if err := r.SetQueryParam("active", qActive); err != nil {
			return err
		}
	}

	// path param keyDerivationInstanceId
	if err := r.SetPathParam("keyDerivationInstanceId", o.KeyDerivationInstanceID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}