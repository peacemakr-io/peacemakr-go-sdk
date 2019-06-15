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

// UpdateExpireUseDomainReader is a Reader for the UpdateExpireUseDomain structure.
type UpdateExpireUseDomainReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateExpireUseDomainReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewUpdateExpireUseDomainOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewUpdateExpireUseDomainBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 401:
		result := NewUpdateExpireUseDomainUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 403:
		result := NewUpdateExpireUseDomainForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 500:
		result := NewUpdateExpireUseDomainInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewUpdateExpireUseDomainOK creates a UpdateExpireUseDomainOK with default headers values
func NewUpdateExpireUseDomainOK() *UpdateExpireUseDomainOK {
	return &UpdateExpireUseDomainOK{}
}

/*UpdateExpireUseDomainOK handles this case with default header values.

Successfully expired use doamin.
*/
type UpdateExpireUseDomainOK struct {
}

func (o *UpdateExpireUseDomainOK) Error() string {
	return fmt.Sprintf("[POST /crypto/useDomain/{useDomainId}/updateExpire][%d] updateExpireUseDomainOK ", 200)
}

func (o *UpdateExpireUseDomainOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewUpdateExpireUseDomainBadRequest creates a UpdateExpireUseDomainBadRequest with default headers values
func NewUpdateExpireUseDomainBadRequest() *UpdateExpireUseDomainBadRequest {
	return &UpdateExpireUseDomainBadRequest{}
}

/*UpdateExpireUseDomainBadRequest handles this case with default header values.

Unable to process request
*/
type UpdateExpireUseDomainBadRequest struct {
	Payload *models.ErrorResponse
}

func (o *UpdateExpireUseDomainBadRequest) Error() string {
	return fmt.Sprintf("[POST /crypto/useDomain/{useDomainId}/updateExpire][%d] updateExpireUseDomainBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateExpireUseDomainBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateExpireUseDomainUnauthorized creates a UpdateExpireUseDomainUnauthorized with default headers values
func NewUpdateExpireUseDomainUnauthorized() *UpdateExpireUseDomainUnauthorized {
	return &UpdateExpireUseDomainUnauthorized{}
}

/*UpdateExpireUseDomainUnauthorized handles this case with default header values.

Not authenticated to perform request
*/
type UpdateExpireUseDomainUnauthorized struct {
}

func (o *UpdateExpireUseDomainUnauthorized) Error() string {
	return fmt.Sprintf("[POST /crypto/useDomain/{useDomainId}/updateExpire][%d] updateExpireUseDomainUnauthorized ", 401)
}

func (o *UpdateExpireUseDomainUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewUpdateExpireUseDomainForbidden creates a UpdateExpireUseDomainForbidden with default headers values
func NewUpdateExpireUseDomainForbidden() *UpdateExpireUseDomainForbidden {
	return &UpdateExpireUseDomainForbidden{}
}

/*UpdateExpireUseDomainForbidden handles this case with default header values.

Not authorized to perform request
*/
type UpdateExpireUseDomainForbidden struct {
}

func (o *UpdateExpireUseDomainForbidden) Error() string {
	return fmt.Sprintf("[POST /crypto/useDomain/{useDomainId}/updateExpire][%d] updateExpireUseDomainForbidden ", 403)
}

func (o *UpdateExpireUseDomainForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewUpdateExpireUseDomainInternalServerError creates a UpdateExpireUseDomainInternalServerError with default headers values
func NewUpdateExpireUseDomainInternalServerError() *UpdateExpireUseDomainInternalServerError {
	return &UpdateExpireUseDomainInternalServerError{}
}

/*UpdateExpireUseDomainInternalServerError handles this case with default header values.

Unrecoverable internal error
*/
type UpdateExpireUseDomainInternalServerError struct {
	Payload *models.ErrorResponse
}

func (o *UpdateExpireUseDomainInternalServerError) Error() string {
	return fmt.Sprintf("[POST /crypto/useDomain/{useDomainId}/updateExpire][%d] updateExpireUseDomainInternalServerError  %+v", 500, o.Payload)
}

func (o *UpdateExpireUseDomainInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}