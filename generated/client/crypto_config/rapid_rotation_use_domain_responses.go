// Code generated by go-swagger; DO NOT EDIT.

package crypto_config

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/notasecret/peacemakr-go-sdk/generated/models"
)

// RapidRotationUseDomainReader is a Reader for the RapidRotationUseDomain structure.
type RapidRotationUseDomainReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RapidRotationUseDomainReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewRapidRotationUseDomainOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewRapidRotationUseDomainBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 401:
		result := NewRapidRotationUseDomainUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 403:
		result := NewRapidRotationUseDomainForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 500:
		result := NewRapidRotationUseDomainInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewRapidRotationUseDomainOK creates a RapidRotationUseDomainOK with default headers values
func NewRapidRotationUseDomainOK() *RapidRotationUseDomainOK {
	return &RapidRotationUseDomainOK{}
}

/*RapidRotationUseDomainOK handles this case with default header values.

Successfully rotated this use doamin
*/
type RapidRotationUseDomainOK struct {
}

func (o *RapidRotationUseDomainOK) Error() string {
	return fmt.Sprintf("[POST /crypto/useDomain/{useDomainId}/rapidRotation][%d] rapidRotationUseDomainOK ", 200)
}

func (o *RapidRotationUseDomainOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRapidRotationUseDomainBadRequest creates a RapidRotationUseDomainBadRequest with default headers values
func NewRapidRotationUseDomainBadRequest() *RapidRotationUseDomainBadRequest {
	return &RapidRotationUseDomainBadRequest{}
}

/*RapidRotationUseDomainBadRequest handles this case with default header values.

Unable to process request
*/
type RapidRotationUseDomainBadRequest struct {
	Payload *models.ErrorResponse
}

func (o *RapidRotationUseDomainBadRequest) Error() string {
	return fmt.Sprintf("[POST /crypto/useDomain/{useDomainId}/rapidRotation][%d] rapidRotationUseDomainBadRequest  %+v", 400, o.Payload)
}

func (o *RapidRotationUseDomainBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRapidRotationUseDomainUnauthorized creates a RapidRotationUseDomainUnauthorized with default headers values
func NewRapidRotationUseDomainUnauthorized() *RapidRotationUseDomainUnauthorized {
	return &RapidRotationUseDomainUnauthorized{}
}

/*RapidRotationUseDomainUnauthorized handles this case with default header values.

Not authenticated to perform request
*/
type RapidRotationUseDomainUnauthorized struct {
}

func (o *RapidRotationUseDomainUnauthorized) Error() string {
	return fmt.Sprintf("[POST /crypto/useDomain/{useDomainId}/rapidRotation][%d] rapidRotationUseDomainUnauthorized ", 401)
}

func (o *RapidRotationUseDomainUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRapidRotationUseDomainForbidden creates a RapidRotationUseDomainForbidden with default headers values
func NewRapidRotationUseDomainForbidden() *RapidRotationUseDomainForbidden {
	return &RapidRotationUseDomainForbidden{}
}

/*RapidRotationUseDomainForbidden handles this case with default header values.

Not authorized to perform request
*/
type RapidRotationUseDomainForbidden struct {
}

func (o *RapidRotationUseDomainForbidden) Error() string {
	return fmt.Sprintf("[POST /crypto/useDomain/{useDomainId}/rapidRotation][%d] rapidRotationUseDomainForbidden ", 403)
}

func (o *RapidRotationUseDomainForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRapidRotationUseDomainInternalServerError creates a RapidRotationUseDomainInternalServerError with default headers values
func NewRapidRotationUseDomainInternalServerError() *RapidRotationUseDomainInternalServerError {
	return &RapidRotationUseDomainInternalServerError{}
}

/*RapidRotationUseDomainInternalServerError handles this case with default header values.

Unrecoverable internal error
*/
type RapidRotationUseDomainInternalServerError struct {
	Payload *models.ErrorResponse
}

func (o *RapidRotationUseDomainInternalServerError) Error() string {
	return fmt.Sprintf("[POST /crypto/useDomain/{useDomainId}/rapidRotation][%d] rapidRotationUseDomainInternalServerError  %+v", 500, o.Payload)
}

func (o *RapidRotationUseDomainInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}