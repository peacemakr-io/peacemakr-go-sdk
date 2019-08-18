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

	models "github.com/peacemakr-io/peacemakr-go-sdk/pkg/generated/models"
)

// NewAddUseDomainParams creates a new AddUseDomainParams object
// with the default values initialized.
func NewAddUseDomainParams() *AddUseDomainParams {
	var ()
	return &AddUseDomainParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewAddUseDomainParamsWithTimeout creates a new AddUseDomainParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewAddUseDomainParamsWithTimeout(timeout time.Duration) *AddUseDomainParams {
	var ()
	return &AddUseDomainParams{

		timeout: timeout,
	}
}

// NewAddUseDomainParamsWithContext creates a new AddUseDomainParams object
// with the default values initialized, and the ability to set a context for a request
func NewAddUseDomainParamsWithContext(ctx context.Context) *AddUseDomainParams {
	var ()
	return &AddUseDomainParams{

		Context: ctx,
	}
}

// NewAddUseDomainParamsWithHTTPClient creates a new AddUseDomainParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewAddUseDomainParamsWithHTTPClient(client *http.Client) *AddUseDomainParams {
	var ()
	return &AddUseDomainParams{
		HTTPClient: client,
	}
}

/*AddUseDomainParams contains all the parameters to send to the API endpoint
for the add use domain operation typically these are written to a http.Request
*/
type AddUseDomainParams struct {

	/*CryptoConfigID*/
	CryptoConfigID string
	/*NewUseDomain*/
	NewUseDomain *models.SymmetricKeyUseDomain

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the add use domain params
func (o *AddUseDomainParams) WithTimeout(timeout time.Duration) *AddUseDomainParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the add use domain params
func (o *AddUseDomainParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the add use domain params
func (o *AddUseDomainParams) WithContext(ctx context.Context) *AddUseDomainParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the add use domain params
func (o *AddUseDomainParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the add use domain params
func (o *AddUseDomainParams) WithHTTPClient(client *http.Client) *AddUseDomainParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the add use domain params
func (o *AddUseDomainParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCryptoConfigID adds the cryptoConfigID to the add use domain params
func (o *AddUseDomainParams) WithCryptoConfigID(cryptoConfigID string) *AddUseDomainParams {
	o.SetCryptoConfigID(cryptoConfigID)
	return o
}

// SetCryptoConfigID adds the cryptoConfigId to the add use domain params
func (o *AddUseDomainParams) SetCryptoConfigID(cryptoConfigID string) {
	o.CryptoConfigID = cryptoConfigID
}

// WithNewUseDomain adds the newUseDomain to the add use domain params
func (o *AddUseDomainParams) WithNewUseDomain(newUseDomain *models.SymmetricKeyUseDomain) *AddUseDomainParams {
	o.SetNewUseDomain(newUseDomain)
	return o
}

// SetNewUseDomain adds the newUseDomain to the add use domain params
func (o *AddUseDomainParams) SetNewUseDomain(newUseDomain *models.SymmetricKeyUseDomain) {
	o.NewUseDomain = newUseDomain
}

// WriteToRequest writes these params to a swagger request
func (o *AddUseDomainParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param cryptoConfigId
	if err := r.SetPathParam("cryptoConfigId", o.CryptoConfigID); err != nil {
		return err
	}

	if o.NewUseDomain != nil {
		if err := r.SetBodyParam(o.NewUseDomain); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
