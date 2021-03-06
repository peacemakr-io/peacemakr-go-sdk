// Code generated by go-swagger; DO NOT EDIT.

package crypto_config

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

// NewGetCryptoConfigParams creates a new GetCryptoConfigParams object
// with the default values initialized.
func NewGetCryptoConfigParams() *GetCryptoConfigParams {
	var ()
	return &GetCryptoConfigParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetCryptoConfigParamsWithTimeout creates a new GetCryptoConfigParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetCryptoConfigParamsWithTimeout(timeout time.Duration) *GetCryptoConfigParams {
	var ()
	return &GetCryptoConfigParams{

		timeout: timeout,
	}
}

// NewGetCryptoConfigParamsWithContext creates a new GetCryptoConfigParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetCryptoConfigParamsWithContext(ctx context.Context) *GetCryptoConfigParams {
	var ()
	return &GetCryptoConfigParams{

		Context: ctx,
	}
}

// NewGetCryptoConfigParamsWithHTTPClient creates a new GetCryptoConfigParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetCryptoConfigParamsWithHTTPClient(client *http.Client) *GetCryptoConfigParams {
	var ()
	return &GetCryptoConfigParams{
		HTTPClient: client,
	}
}

/*GetCryptoConfigParams contains all the parameters to send to the API endpoint
for the get crypto config operation typically these are written to a http.Request
*/
type GetCryptoConfigParams struct {

	/*CryptoConfigID*/
	CryptoConfigID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get crypto config params
func (o *GetCryptoConfigParams) WithTimeout(timeout time.Duration) *GetCryptoConfigParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get crypto config params
func (o *GetCryptoConfigParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get crypto config params
func (o *GetCryptoConfigParams) WithContext(ctx context.Context) *GetCryptoConfigParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get crypto config params
func (o *GetCryptoConfigParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get crypto config params
func (o *GetCryptoConfigParams) WithHTTPClient(client *http.Client) *GetCryptoConfigParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get crypto config params
func (o *GetCryptoConfigParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCryptoConfigID adds the cryptoConfigID to the get crypto config params
func (o *GetCryptoConfigParams) WithCryptoConfigID(cryptoConfigID string) *GetCryptoConfigParams {
	o.SetCryptoConfigID(cryptoConfigID)
	return o
}

// SetCryptoConfigID adds the cryptoConfigId to the get crypto config params
func (o *GetCryptoConfigParams) SetCryptoConfigID(cryptoConfigID string) {
	o.CryptoConfigID = cryptoConfigID
}

// WriteToRequest writes these params to a swagger request
func (o *GetCryptoConfigParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param cryptoConfigId
	if err := r.SetPathParam("cryptoConfigId", o.CryptoConfigID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
