// Code generated by go-swagger; DO NOT EDIT.

package client

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/peacemakr-io/peacemakr-go-sdk/pkg/generated/models"
)

// ReturnPagedClientIdsReader is a Reader for the ReturnPagedClientIds structure.
type ReturnPagedClientIdsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ReturnPagedClientIdsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewReturnPagedClientIdsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewReturnPagedClientIdsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 401:
		result := NewReturnPagedClientIdsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 403:
		result := NewReturnPagedClientIdsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 500:
		result := NewReturnPagedClientIdsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewReturnPagedClientIdsOK creates a ReturnPagedClientIdsOK with default headers values
func NewReturnPagedClientIdsOK() *ReturnPagedClientIdsOK {
	return &ReturnPagedClientIdsOK{}
}

/*ReturnPagedClientIdsOK handles this case with default header values.

A list of clientIds in the requested page.
*/
type ReturnPagedClientIdsOK struct {
	Payload *models.PagedArray
}

func (o *ReturnPagedClientIdsOK) Error() string {
	return fmt.Sprintf("[GET /client][%d] returnPagedClientIdsOK  %+v", 200, o.Payload)
}

func (o *ReturnPagedClientIdsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PagedArray)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewReturnPagedClientIdsBadRequest creates a ReturnPagedClientIdsBadRequest with default headers values
func NewReturnPagedClientIdsBadRequest() *ReturnPagedClientIdsBadRequest {
	return &ReturnPagedClientIdsBadRequest{}
}

/*ReturnPagedClientIdsBadRequest handles this case with default header values.

Unable to process request
*/
type ReturnPagedClientIdsBadRequest struct {
}

func (o *ReturnPagedClientIdsBadRequest) Error() string {
	return fmt.Sprintf("[GET /client][%d] returnPagedClientIdsBadRequest ", 400)
}

func (o *ReturnPagedClientIdsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewReturnPagedClientIdsUnauthorized creates a ReturnPagedClientIdsUnauthorized with default headers values
func NewReturnPagedClientIdsUnauthorized() *ReturnPagedClientIdsUnauthorized {
	return &ReturnPagedClientIdsUnauthorized{}
}

/*ReturnPagedClientIdsUnauthorized handles this case with default header values.

Not authenticated
*/
type ReturnPagedClientIdsUnauthorized struct {
}

func (o *ReturnPagedClientIdsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /client][%d] returnPagedClientIdsUnauthorized ", 401)
}

func (o *ReturnPagedClientIdsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewReturnPagedClientIdsForbidden creates a ReturnPagedClientIdsForbidden with default headers values
func NewReturnPagedClientIdsForbidden() *ReturnPagedClientIdsForbidden {
	return &ReturnPagedClientIdsForbidden{}
}

/*ReturnPagedClientIdsForbidden handles this case with default header values.

Not authorized
*/
type ReturnPagedClientIdsForbidden struct {
}

func (o *ReturnPagedClientIdsForbidden) Error() string {
	return fmt.Sprintf("[GET /client][%d] returnPagedClientIdsForbidden ", 403)
}

func (o *ReturnPagedClientIdsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewReturnPagedClientIdsInternalServerError creates a ReturnPagedClientIdsInternalServerError with default headers values
func NewReturnPagedClientIdsInternalServerError() *ReturnPagedClientIdsInternalServerError {
	return &ReturnPagedClientIdsInternalServerError{}
}

/*ReturnPagedClientIdsInternalServerError handles this case with default header values.

Internal server error
*/
type ReturnPagedClientIdsInternalServerError struct {
}

func (o *ReturnPagedClientIdsInternalServerError) Error() string {
	return fmt.Sprintf("[GET /client][%d] returnPagedClientIdsInternalServerError ", 500)
}

func (o *ReturnPagedClientIdsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
