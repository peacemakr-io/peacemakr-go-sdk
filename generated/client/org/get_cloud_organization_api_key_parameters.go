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

// NewGetCloudOrganizationAPIKeyParams creates a new GetCloudOrganizationAPIKeyParams object
// with the default values initialized.
func NewGetCloudOrganizationAPIKeyParams() *GetCloudOrganizationAPIKeyParams {

	return &GetCloudOrganizationAPIKeyParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetCloudOrganizationAPIKeyParamsWithTimeout creates a new GetCloudOrganizationAPIKeyParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetCloudOrganizationAPIKeyParamsWithTimeout(timeout time.Duration) *GetCloudOrganizationAPIKeyParams {

	return &GetCloudOrganizationAPIKeyParams{

		timeout: timeout,
	}
}

// NewGetCloudOrganizationAPIKeyParamsWithContext creates a new GetCloudOrganizationAPIKeyParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetCloudOrganizationAPIKeyParamsWithContext(ctx context.Context) *GetCloudOrganizationAPIKeyParams {

	return &GetCloudOrganizationAPIKeyParams{

		Context: ctx,
	}
}

// NewGetCloudOrganizationAPIKeyParamsWithHTTPClient creates a new GetCloudOrganizationAPIKeyParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetCloudOrganizationAPIKeyParamsWithHTTPClient(client *http.Client) *GetCloudOrganizationAPIKeyParams {

	return &GetCloudOrganizationAPIKeyParams{
		HTTPClient: client,
	}
}

/*GetCloudOrganizationAPIKeyParams contains all the parameters to send to the API endpoint
for the get cloud organization API key operation typically these are written to a http.Request
*/
type GetCloudOrganizationAPIKeyParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get cloud organization API key params
func (o *GetCloudOrganizationAPIKeyParams) WithTimeout(timeout time.Duration) *GetCloudOrganizationAPIKeyParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get cloud organization API key params
func (o *GetCloudOrganizationAPIKeyParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get cloud organization API key params
func (o *GetCloudOrganizationAPIKeyParams) WithContext(ctx context.Context) *GetCloudOrganizationAPIKeyParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get cloud organization API key params
func (o *GetCloudOrganizationAPIKeyParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get cloud organization API key params
func (o *GetCloudOrganizationAPIKeyParams) WithHTTPClient(client *http.Client) *GetCloudOrganizationAPIKeyParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get cloud organization API key params
func (o *GetCloudOrganizationAPIKeyParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *GetCloudOrganizationAPIKeyParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
