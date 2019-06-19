// Code generated by go-swagger; DO NOT EDIT.

package client

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/notasecret/peacemakr-go-sdk/generated/models"
)

// AddClientPublicKeyReader is a Reader for the AddClientPublicKey structure.
type AddClientPublicKeyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AddClientPublicKeyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewAddClientPublicKeyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewAddClientPublicKeyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 401:
		result := NewAddClientPublicKeyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 403:
		result := NewAddClientPublicKeyForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 500:
		result := NewAddClientPublicKeyInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewAddClientPublicKeyOK creates a AddClientPublicKeyOK with default headers values
func NewAddClientPublicKeyOK() *AddClientPublicKeyOK {
	return &AddClientPublicKeyOK{}
}

/*AddClientPublicKeyOK handles this case with default header values.

Public key for the client successfully added
*/
type AddClientPublicKeyOK struct {
	Payload *models.PublicKey
}

func (o *AddClientPublicKeyOK) Error() string {
	return fmt.Sprintf("[POST /client/{clientId}/addPublicKey][%d] addClientPublicKeyOK  %+v", 200, o.Payload)
}

func (o *AddClientPublicKeyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PublicKey)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAddClientPublicKeyBadRequest creates a AddClientPublicKeyBadRequest with default headers values
func NewAddClientPublicKeyBadRequest() *AddClientPublicKeyBadRequest {
	return &AddClientPublicKeyBadRequest{}
}

/*AddClientPublicKeyBadRequest handles this case with default header values.

Unable to process request
*/
type AddClientPublicKeyBadRequest struct {
}

func (o *AddClientPublicKeyBadRequest) Error() string {
	return fmt.Sprintf("[POST /client/{clientId}/addPublicKey][%d] addClientPublicKeyBadRequest ", 400)
}

func (o *AddClientPublicKeyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewAddClientPublicKeyUnauthorized creates a AddClientPublicKeyUnauthorized with default headers values
func NewAddClientPublicKeyUnauthorized() *AddClientPublicKeyUnauthorized {
	return &AddClientPublicKeyUnauthorized{}
}

/*AddClientPublicKeyUnauthorized handles this case with default header values.

Not authenticated
*/
type AddClientPublicKeyUnauthorized struct {
}

func (o *AddClientPublicKeyUnauthorized) Error() string {
	return fmt.Sprintf("[POST /client/{clientId}/addPublicKey][%d] addClientPublicKeyUnauthorized ", 401)
}

func (o *AddClientPublicKeyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewAddClientPublicKeyForbidden creates a AddClientPublicKeyForbidden with default headers values
func NewAddClientPublicKeyForbidden() *AddClientPublicKeyForbidden {
	return &AddClientPublicKeyForbidden{}
}

/*AddClientPublicKeyForbidden handles this case with default header values.

Not authorized
*/
type AddClientPublicKeyForbidden struct {
}

func (o *AddClientPublicKeyForbidden) Error() string {
	return fmt.Sprintf("[POST /client/{clientId}/addPublicKey][%d] addClientPublicKeyForbidden ", 403)
}

func (o *AddClientPublicKeyForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewAddClientPublicKeyInternalServerError creates a AddClientPublicKeyInternalServerError with default headers values
func NewAddClientPublicKeyInternalServerError() *AddClientPublicKeyInternalServerError {
	return &AddClientPublicKeyInternalServerError{}
}

/*AddClientPublicKeyInternalServerError handles this case with default header values.

Internal server error
*/
type AddClientPublicKeyInternalServerError struct {
}

func (o *AddClientPublicKeyInternalServerError) Error() string {
	return fmt.Sprintf("[POST /client/{clientId}/addPublicKey][%d] addClientPublicKeyInternalServerError ", 500)
}

func (o *AddClientPublicKeyInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}