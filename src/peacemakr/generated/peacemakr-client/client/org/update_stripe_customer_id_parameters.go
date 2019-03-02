// Code generated by go-swagger; DO NOT EDIT.

package org

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

// NewUpdateStripeCustomerIDParams creates a new UpdateStripeCustomerIDParams object
// with the default values initialized.
func NewUpdateStripeCustomerIDParams() *UpdateStripeCustomerIDParams {
	var ()
	return &UpdateStripeCustomerIDParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateStripeCustomerIDParamsWithTimeout creates a new UpdateStripeCustomerIDParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewUpdateStripeCustomerIDParamsWithTimeout(timeout time.Duration) *UpdateStripeCustomerIDParams {
	var ()
	return &UpdateStripeCustomerIDParams{

		timeout: timeout,
	}
}

// NewUpdateStripeCustomerIDParamsWithContext creates a new UpdateStripeCustomerIDParams object
// with the default values initialized, and the ability to set a context for a request
func NewUpdateStripeCustomerIDParamsWithContext(ctx context.Context) *UpdateStripeCustomerIDParams {
	var ()
	return &UpdateStripeCustomerIDParams{

		Context: ctx,
	}
}

// NewUpdateStripeCustomerIDParamsWithHTTPClient creates a new UpdateStripeCustomerIDParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewUpdateStripeCustomerIDParamsWithHTTPClient(client *http.Client) *UpdateStripeCustomerIDParams {
	var ()
	return &UpdateStripeCustomerIDParams{
		HTTPClient: client,
	}
}

/*UpdateStripeCustomerIDParams contains all the parameters to send to the API endpoint
for the update stripe customer Id operation typically these are written to a http.Request
*/
type UpdateStripeCustomerIDParams struct {

	/*StripeCustomerID*/
	StripeCustomerID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the update stripe customer Id params
func (o *UpdateStripeCustomerIDParams) WithTimeout(timeout time.Duration) *UpdateStripeCustomerIDParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update stripe customer Id params
func (o *UpdateStripeCustomerIDParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update stripe customer Id params
func (o *UpdateStripeCustomerIDParams) WithContext(ctx context.Context) *UpdateStripeCustomerIDParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update stripe customer Id params
func (o *UpdateStripeCustomerIDParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update stripe customer Id params
func (o *UpdateStripeCustomerIDParams) WithHTTPClient(client *http.Client) *UpdateStripeCustomerIDParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update stripe customer Id params
func (o *UpdateStripeCustomerIDParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithStripeCustomerID adds the stripeCustomerID to the update stripe customer Id params
func (o *UpdateStripeCustomerIDParams) WithStripeCustomerID(stripeCustomerID string) *UpdateStripeCustomerIDParams {
	o.SetStripeCustomerID(stripeCustomerID)
	return o
}

// SetStripeCustomerID adds the stripeCustomerId to the update stripe customer Id params
func (o *UpdateStripeCustomerIDParams) SetStripeCustomerID(stripeCustomerID string) {
	o.StripeCustomerID = stripeCustomerID
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateStripeCustomerIDParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param stripeCustomerId
	qrStripeCustomerID := o.StripeCustomerID
	qStripeCustomerID := qrStripeCustomerID
	if qStripeCustomerID != "" {
		if err := r.SetQueryParam("stripeCustomerId", qStripeCustomerID); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
