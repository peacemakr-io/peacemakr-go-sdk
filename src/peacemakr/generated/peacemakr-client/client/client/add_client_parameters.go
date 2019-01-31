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

	models "peacemakr/generated/peacemakr-client/models"
)

// NewAddClientParams creates a new AddClientParams object
// with the default values initialized.
func NewAddClientParams() *AddClientParams {
	var ()
	return &AddClientParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewAddClientParamsWithTimeout creates a new AddClientParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewAddClientParamsWithTimeout(timeout time.Duration) *AddClientParams {
	var ()
	return &AddClientParams{

		timeout: timeout,
	}
}

// NewAddClientParamsWithContext creates a new AddClientParams object
// with the default values initialized, and the ability to set a context for a request
func NewAddClientParamsWithContext(ctx context.Context) *AddClientParams {
	var ()
	return &AddClientParams{

		Context: ctx,
	}
}

// NewAddClientParamsWithHTTPClient creates a new AddClientParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewAddClientParamsWithHTTPClient(client *http.Client) *AddClientParams {
	var ()
	return &AddClientParams{
		HTTPClient: client,
	}
}

/*AddClientParams contains all the parameters to send to the API endpoint
for the add client operation typically these are written to a http.Request
*/
type AddClientParams struct {

	/*Client*/
	Client *models.Client

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the add client params
func (o *AddClientParams) WithTimeout(timeout time.Duration) *AddClientParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the add client params
func (o *AddClientParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the add client params
func (o *AddClientParams) WithContext(ctx context.Context) *AddClientParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the add client params
func (o *AddClientParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the add client params
func (o *AddClientParams) WithHTTPClient(client *http.Client) *AddClientParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the add client params
func (o *AddClientParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithClient adds the client to the add client params
func (o *AddClientParams) WithClient(client *models.Client) *AddClientParams {
	o.SetClient(client)
	return o
}

// SetClient adds the client to the add client params
func (o *AddClientParams) SetClient(client *models.Client) {
	o.Client = client
}

// WriteToRequest writes these params to a swagger request
func (o *AddClientParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Client != nil {
		if err := r.SetBodyParam(o.Client); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
