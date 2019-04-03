// Code generated by go-swagger; DO NOT EDIT.

package key_service

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

// NewGetPublicKeyParams creates a new GetPublicKeyParams object
// with the default values initialized.
func NewGetPublicKeyParams() *GetPublicKeyParams {
	var ()
	return &GetPublicKeyParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetPublicKeyParamsWithTimeout creates a new GetPublicKeyParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetPublicKeyParamsWithTimeout(timeout time.Duration) *GetPublicKeyParams {
	var ()
	return &GetPublicKeyParams{

		timeout: timeout,
	}
}

// NewGetPublicKeyParamsWithContext creates a new GetPublicKeyParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetPublicKeyParamsWithContext(ctx context.Context) *GetPublicKeyParams {
	var ()
	return &GetPublicKeyParams{

		Context: ctx,
	}
}

// NewGetPublicKeyParamsWithHTTPClient creates a new GetPublicKeyParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetPublicKeyParamsWithHTTPClient(client *http.Client) *GetPublicKeyParams {
	var ()
	return &GetPublicKeyParams{
		HTTPClient: client,
	}
}

/*GetPublicKeyParams contains all the parameters to send to the API endpoint
for the get public key operation typically these are written to a http.Request
*/
type GetPublicKeyParams struct {

	/*KeyID*/
	KeyID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get public key params
func (o *GetPublicKeyParams) WithTimeout(timeout time.Duration) *GetPublicKeyParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get public key params
func (o *GetPublicKeyParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get public key params
func (o *GetPublicKeyParams) WithContext(ctx context.Context) *GetPublicKeyParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get public key params
func (o *GetPublicKeyParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get public key params
func (o *GetPublicKeyParams) WithHTTPClient(client *http.Client) *GetPublicKeyParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get public key params
func (o *GetPublicKeyParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithKeyID adds the keyID to the get public key params
func (o *GetPublicKeyParams) WithKeyID(keyID string) *GetPublicKeyParams {
	o.SetKeyID(keyID)
	return o
}

// SetKeyID adds the keyId to the get public key params
func (o *GetPublicKeyParams) SetKeyID(keyID string) {
	o.KeyID = keyID
}

// WriteToRequest writes these params to a swagger request
func (o *GetPublicKeyParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param keyID
	if err := r.SetPathParam("keyID", o.KeyID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}