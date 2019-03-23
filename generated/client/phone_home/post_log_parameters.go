// Code generated by go-swagger; DO NOT EDIT.

package phone_home

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

	models "github.com/notasecret/peacemakr-go-sdk/generated/models"
)

// NewPostLogParams creates a new PostLogParams object
// with the default values initialized.
func NewPostLogParams() *PostLogParams {
	var ()
	return &PostLogParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewPostLogParamsWithTimeout creates a new PostLogParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewPostLogParamsWithTimeout(timeout time.Duration) *PostLogParams {
	var ()
	return &PostLogParams{

		timeout: timeout,
	}
}

// NewPostLogParamsWithContext creates a new PostLogParams object
// with the default values initialized, and the ability to set a context for a request
func NewPostLogParamsWithContext(ctx context.Context) *PostLogParams {
	var ()
	return &PostLogParams{

		Context: ctx,
	}
}

// NewPostLogParamsWithHTTPClient creates a new PostLogParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewPostLogParamsWithHTTPClient(client *http.Client) *PostLogParams {
	var ()
	return &PostLogParams{
		HTTPClient: client,
	}
}

/*PostLogParams contains all the parameters to send to the API endpoint
for the post log operation typically these are written to a http.Request
*/
type PostLogParams struct {

	/*Log*/
	Log *models.Log

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the post log params
func (o *PostLogParams) WithTimeout(timeout time.Duration) *PostLogParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the post log params
func (o *PostLogParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the post log params
func (o *PostLogParams) WithContext(ctx context.Context) *PostLogParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the post log params
func (o *PostLogParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the post log params
func (o *PostLogParams) WithHTTPClient(client *http.Client) *PostLogParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the post log params
func (o *PostLogParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithLog adds the log to the post log params
func (o *PostLogParams) WithLog(log *models.Log) *PostLogParams {
	o.SetLog(log)
	return o
}

// SetLog adds the log to the post log params
func (o *PostLogParams) SetLog(log *models.Log) {
	o.Log = log
}

// WriteToRequest writes these params to a swagger request
func (o *PostLogParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Log != nil {
		if err := r.SetBodyParam(o.Log); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
