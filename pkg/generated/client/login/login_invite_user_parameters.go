// Code generated by go-swagger; DO NOT EDIT.

package login

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

// NewLoginInviteUserParams creates a new LoginInviteUserParams object
// with the default values initialized.
func NewLoginInviteUserParams() *LoginInviteUserParams {
	var ()
	return &LoginInviteUserParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewLoginInviteUserParamsWithTimeout creates a new LoginInviteUserParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewLoginInviteUserParamsWithTimeout(timeout time.Duration) *LoginInviteUserParams {
	var ()
	return &LoginInviteUserParams{

		timeout: timeout,
	}
}

// NewLoginInviteUserParamsWithContext creates a new LoginInviteUserParams object
// with the default values initialized, and the ability to set a context for a request
func NewLoginInviteUserParamsWithContext(ctx context.Context) *LoginInviteUserParams {
	var ()
	return &LoginInviteUserParams{

		Context: ctx,
	}
}

// NewLoginInviteUserParamsWithHTTPClient creates a new LoginInviteUserParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewLoginInviteUserParamsWithHTTPClient(client *http.Client) *LoginInviteUserParams {
	var ()
	return &LoginInviteUserParams{
		HTTPClient: client,
	}
}

/*LoginInviteUserParams contains all the parameters to send to the API endpoint
for the login invite user operation typically these are written to a http.Request
*/
type LoginInviteUserParams struct {

	/*Email*/
	Email string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the login invite user params
func (o *LoginInviteUserParams) WithTimeout(timeout time.Duration) *LoginInviteUserParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the login invite user params
func (o *LoginInviteUserParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the login invite user params
func (o *LoginInviteUserParams) WithContext(ctx context.Context) *LoginInviteUserParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the login invite user params
func (o *LoginInviteUserParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the login invite user params
func (o *LoginInviteUserParams) WithHTTPClient(client *http.Client) *LoginInviteUserParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the login invite user params
func (o *LoginInviteUserParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithEmail adds the email to the login invite user params
func (o *LoginInviteUserParams) WithEmail(email string) *LoginInviteUserParams {
	o.SetEmail(email)
	return o
}

// SetEmail adds the email to the login invite user params
func (o *LoginInviteUserParams) SetEmail(email string) {
	o.Email = email
}

// WriteToRequest writes these params to a swagger request
func (o *LoginInviteUserParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param email
	qrEmail := o.Email
	qEmail := qrEmail
	if qEmail != "" {
		if err := r.SetQueryParam("email", qEmail); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
