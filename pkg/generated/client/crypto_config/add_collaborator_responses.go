// Code generated by go-swagger; DO NOT EDIT.

package crypto_config

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/peacemakr-io/peacemakr-go-sdk/pkg/generated/models"
)

// AddCollaboratorReader is a Reader for the AddCollaborator structure.
type AddCollaboratorReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AddCollaboratorReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewAddCollaboratorOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewAddCollaboratorBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 401:
		result := NewAddCollaboratorUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 403:
		result := NewAddCollaboratorForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 500:
		result := NewAddCollaboratorInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewAddCollaboratorOK creates a AddCollaboratorOK with default headers values
func NewAddCollaboratorOK() *AddCollaboratorOK {
	return &AddCollaboratorOK{}
}

/*AddCollaboratorOK handles this case with default header values.

Successfully added collaborator
*/
type AddCollaboratorOK struct {
	Payload *models.TinyOrg
}

func (o *AddCollaboratorOK) Error() string {
	return fmt.Sprintf("[POST /crypto/useDomain/{useDomainId}/collaborator][%d] addCollaboratorOK  %+v", 200, o.Payload)
}

func (o *AddCollaboratorOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.TinyOrg)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAddCollaboratorBadRequest creates a AddCollaboratorBadRequest with default headers values
func NewAddCollaboratorBadRequest() *AddCollaboratorBadRequest {
	return &AddCollaboratorBadRequest{}
}

/*AddCollaboratorBadRequest handles this case with default header values.

Unable to process request
*/
type AddCollaboratorBadRequest struct {
	Payload *models.ErrorResponse
}

func (o *AddCollaboratorBadRequest) Error() string {
	return fmt.Sprintf("[POST /crypto/useDomain/{useDomainId}/collaborator][%d] addCollaboratorBadRequest  %+v", 400, o.Payload)
}

func (o *AddCollaboratorBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAddCollaboratorUnauthorized creates a AddCollaboratorUnauthorized with default headers values
func NewAddCollaboratorUnauthorized() *AddCollaboratorUnauthorized {
	return &AddCollaboratorUnauthorized{}
}

/*AddCollaboratorUnauthorized handles this case with default header values.

Not authenticated to perform request
*/
type AddCollaboratorUnauthorized struct {
}

func (o *AddCollaboratorUnauthorized) Error() string {
	return fmt.Sprintf("[POST /crypto/useDomain/{useDomainId}/collaborator][%d] addCollaboratorUnauthorized ", 401)
}

func (o *AddCollaboratorUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewAddCollaboratorForbidden creates a AddCollaboratorForbidden with default headers values
func NewAddCollaboratorForbidden() *AddCollaboratorForbidden {
	return &AddCollaboratorForbidden{}
}

/*AddCollaboratorForbidden handles this case with default header values.

Not authorized to perform request
*/
type AddCollaboratorForbidden struct {
}

func (o *AddCollaboratorForbidden) Error() string {
	return fmt.Sprintf("[POST /crypto/useDomain/{useDomainId}/collaborator][%d] addCollaboratorForbidden ", 403)
}

func (o *AddCollaboratorForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewAddCollaboratorInternalServerError creates a AddCollaboratorInternalServerError with default headers values
func NewAddCollaboratorInternalServerError() *AddCollaboratorInternalServerError {
	return &AddCollaboratorInternalServerError{}
}

/*AddCollaboratorInternalServerError handles this case with default header values.

Unrecoverable internal error
*/
type AddCollaboratorInternalServerError struct {
	Payload *models.ErrorResponse
}

func (o *AddCollaboratorInternalServerError) Error() string {
	return fmt.Sprintf("[POST /crypto/useDomain/{useDomainId}/collaborator][%d] addCollaboratorInternalServerError  %+v", 500, o.Payload)
}

func (o *AddCollaboratorInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
