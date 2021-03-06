// Code generated by go-swagger; DO NOT EDIT.

package org

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/peacemakr-io/peacemakr-go-sdk/pkg/generated/models"
)

// UpdateStripeCustomerIDReader is a Reader for the UpdateStripeCustomerID structure.
type UpdateStripeCustomerIDReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateStripeCustomerIDReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewUpdateStripeCustomerIDOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewUpdateStripeCustomerIDBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 401:
		result := NewUpdateStripeCustomerIDUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewUpdateStripeCustomerIDOK creates a UpdateStripeCustomerIDOK with default headers values
func NewUpdateStripeCustomerIDOK() *UpdateStripeCustomerIDOK {
	return &UpdateStripeCustomerIDOK{}
}

/*UpdateStripeCustomerIDOK handles this case with default header values.

Successfully updated stripe customer id
*/
type UpdateStripeCustomerIDOK struct {
	Payload *models.APIKey
}

func (o *UpdateStripeCustomerIDOK) Error() string {
	return fmt.Sprintf("[POST /org/stripeId][%d] updateStripeCustomerIdOK  %+v", 200, o.Payload)
}

func (o *UpdateStripeCustomerIDOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIKey)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateStripeCustomerIDBadRequest creates a UpdateStripeCustomerIDBadRequest with default headers values
func NewUpdateStripeCustomerIDBadRequest() *UpdateStripeCustomerIDBadRequest {
	return &UpdateStripeCustomerIDBadRequest{}
}

/*UpdateStripeCustomerIDBadRequest handles this case with default header values.

Unable to process request
*/
type UpdateStripeCustomerIDBadRequest struct {
}

func (o *UpdateStripeCustomerIDBadRequest) Error() string {
	return fmt.Sprintf("[POST /org/stripeId][%d] updateStripeCustomerIdBadRequest ", 400)
}

func (o *UpdateStripeCustomerIDBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewUpdateStripeCustomerIDUnauthorized creates a UpdateStripeCustomerIDUnauthorized with default headers values
func NewUpdateStripeCustomerIDUnauthorized() *UpdateStripeCustomerIDUnauthorized {
	return &UpdateStripeCustomerIDUnauthorized{}
}

/*UpdateStripeCustomerIDUnauthorized handles this case with default header values.

Not authenticated to perform request
*/
type UpdateStripeCustomerIDUnauthorized struct {
}

func (o *UpdateStripeCustomerIDUnauthorized) Error() string {
	return fmt.Sprintf("[POST /org/stripeId][%d] updateStripeCustomerIdUnauthorized ", 401)
}

func (o *UpdateStripeCustomerIDUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
