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

// DeleteAdminFromOrgReader is a Reader for the DeleteAdminFromOrg structure.
type DeleteAdminFromOrgReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteAdminFromOrgReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewDeleteAdminFromOrgOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewDeleteAdminFromOrgBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 401:
		result := NewDeleteAdminFromOrgUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 500:
		result := NewDeleteAdminFromOrgInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewDeleteAdminFromOrgOK creates a DeleteAdminFromOrgOK with default headers values
func NewDeleteAdminFromOrgOK() *DeleteAdminFromOrgOK {
	return &DeleteAdminFromOrgOK{}
}

/*DeleteAdminFromOrgOK handles this case with default header values.

Successful deletion of an existing admin from org.
*/
type DeleteAdminFromOrgOK struct {
}

func (o *DeleteAdminFromOrgOK) Error() string {
	return fmt.Sprintf("[DELETE /org/admin/{email}][%d] deleteAdminFromOrgOK ", 200)
}

func (o *DeleteAdminFromOrgOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteAdminFromOrgBadRequest creates a DeleteAdminFromOrgBadRequest with default headers values
func NewDeleteAdminFromOrgBadRequest() *DeleteAdminFromOrgBadRequest {
	return &DeleteAdminFromOrgBadRequest{}
}

/*DeleteAdminFromOrgBadRequest handles this case with default header values.

Unable to process request
*/
type DeleteAdminFromOrgBadRequest struct {
	Payload *models.ErrorResponse
}

func (o *DeleteAdminFromOrgBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /org/admin/{email}][%d] deleteAdminFromOrgBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteAdminFromOrgBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteAdminFromOrgUnauthorized creates a DeleteAdminFromOrgUnauthorized with default headers values
func NewDeleteAdminFromOrgUnauthorized() *DeleteAdminFromOrgUnauthorized {
	return &DeleteAdminFromOrgUnauthorized{}
}

/*DeleteAdminFromOrgUnauthorized handles this case with default header values.

Not authenticated to perform request
*/
type DeleteAdminFromOrgUnauthorized struct {
}

func (o *DeleteAdminFromOrgUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /org/admin/{email}][%d] deleteAdminFromOrgUnauthorized ", 401)
}

func (o *DeleteAdminFromOrgUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteAdminFromOrgInternalServerError creates a DeleteAdminFromOrgInternalServerError with default headers values
func NewDeleteAdminFromOrgInternalServerError() *DeleteAdminFromOrgInternalServerError {
	return &DeleteAdminFromOrgInternalServerError{}
}

/*DeleteAdminFromOrgInternalServerError handles this case with default header values.

Unrecoverable error
*/
type DeleteAdminFromOrgInternalServerError struct {
	Payload *models.ErrorResponse
}

func (o *DeleteAdminFromOrgInternalServerError) Error() string {
	return fmt.Sprintf("[DELETE /org/admin/{email}][%d] deleteAdminFromOrgInternalServerError  %+v", 500, o.Payload)
}

func (o *DeleteAdminFromOrgInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
