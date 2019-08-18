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

// AddAdminToOrgReader is a Reader for the AddAdminToOrg structure.
type AddAdminToOrgReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AddAdminToOrgReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewAddAdminToOrgOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewAddAdminToOrgBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 401:
		result := NewAddAdminToOrgUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 500:
		result := NewAddAdminToOrgInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewAddAdminToOrgOK creates a AddAdminToOrgOK with default headers values
func NewAddAdminToOrgOK() *AddAdminToOrgOK {
	return &AddAdminToOrgOK{}
}

/*AddAdminToOrgOK handles this case with default header values.

Successful addition of a new admin to this org
*/
type AddAdminToOrgOK struct {
	Payload *models.Contact
}

func (o *AddAdminToOrgOK) Error() string {
	return fmt.Sprintf("[POST /org/admin][%d] addAdminToOrgOK  %+v", 200, o.Payload)
}

func (o *AddAdminToOrgOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Contact)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAddAdminToOrgBadRequest creates a AddAdminToOrgBadRequest with default headers values
func NewAddAdminToOrgBadRequest() *AddAdminToOrgBadRequest {
	return &AddAdminToOrgBadRequest{}
}

/*AddAdminToOrgBadRequest handles this case with default header values.

Unable to process request
*/
type AddAdminToOrgBadRequest struct {
	Payload *models.ErrorResponse
}

func (o *AddAdminToOrgBadRequest) Error() string {
	return fmt.Sprintf("[POST /org/admin][%d] addAdminToOrgBadRequest  %+v", 400, o.Payload)
}

func (o *AddAdminToOrgBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAddAdminToOrgUnauthorized creates a AddAdminToOrgUnauthorized with default headers values
func NewAddAdminToOrgUnauthorized() *AddAdminToOrgUnauthorized {
	return &AddAdminToOrgUnauthorized{}
}

/*AddAdminToOrgUnauthorized handles this case with default header values.

Not authenticated to perform request
*/
type AddAdminToOrgUnauthorized struct {
}

func (o *AddAdminToOrgUnauthorized) Error() string {
	return fmt.Sprintf("[POST /org/admin][%d] addAdminToOrgUnauthorized ", 401)
}

func (o *AddAdminToOrgUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewAddAdminToOrgInternalServerError creates a AddAdminToOrgInternalServerError with default headers values
func NewAddAdminToOrgInternalServerError() *AddAdminToOrgInternalServerError {
	return &AddAdminToOrgInternalServerError{}
}

/*AddAdminToOrgInternalServerError handles this case with default header values.

Unrecoverable error
*/
type AddAdminToOrgInternalServerError struct {
	Payload *models.ErrorResponse
}

func (o *AddAdminToOrgInternalServerError) Error() string {
	return fmt.Sprintf("[POST /org/admin][%d] addAdminToOrgInternalServerError  %+v", 500, o.Payload)
}

func (o *AddAdminToOrgInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
