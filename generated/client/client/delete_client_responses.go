// Code generated by go-swagger; DO NOT EDIT.

package client

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/peacemakr-io/peacemakr-go-sdk/generated/models"
)

// DeleteClientReader is a Reader for the DeleteClient structure.
type DeleteClientReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteClientReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewDeleteClientOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewDeleteClientBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 401:
		result := NewDeleteClientUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 403:
		result := NewDeleteClientForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 500:
		result := NewDeleteClientInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewDeleteClientOK creates a DeleteClientOK with default headers values
func NewDeleteClientOK() *DeleteClientOK {
	return &DeleteClientOK{}
}

/*DeleteClientOK handles this case with default header values.

Successful update of an existing client.
*/
type DeleteClientOK struct {
	Payload *models.Client
}

func (o *DeleteClientOK) Error() string {
	return fmt.Sprintf("[DELETE /client/{clientId}][%d] deleteClientOK  %+v", 200, o.Payload)
}

func (o *DeleteClientOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Client)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteClientBadRequest creates a DeleteClientBadRequest with default headers values
func NewDeleteClientBadRequest() *DeleteClientBadRequest {
	return &DeleteClientBadRequest{}
}

/*DeleteClientBadRequest handles this case with default header values.

Unable to process request
*/
type DeleteClientBadRequest struct {
}

func (o *DeleteClientBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /client/{clientId}][%d] deleteClientBadRequest ", 400)
}

func (o *DeleteClientBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteClientUnauthorized creates a DeleteClientUnauthorized with default headers values
func NewDeleteClientUnauthorized() *DeleteClientUnauthorized {
	return &DeleteClientUnauthorized{}
}

/*DeleteClientUnauthorized handles this case with default header values.

Not authenticated
*/
type DeleteClientUnauthorized struct {
}

func (o *DeleteClientUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /client/{clientId}][%d] deleteClientUnauthorized ", 401)
}

func (o *DeleteClientUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteClientForbidden creates a DeleteClientForbidden with default headers values
func NewDeleteClientForbidden() *DeleteClientForbidden {
	return &DeleteClientForbidden{}
}

/*DeleteClientForbidden handles this case with default header values.

Not authorized
*/
type DeleteClientForbidden struct {
}

func (o *DeleteClientForbidden) Error() string {
	return fmt.Sprintf("[DELETE /client/{clientId}][%d] deleteClientForbidden ", 403)
}

func (o *DeleteClientForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteClientInternalServerError creates a DeleteClientInternalServerError with default headers values
func NewDeleteClientInternalServerError() *DeleteClientInternalServerError {
	return &DeleteClientInternalServerError{}
}

/*DeleteClientInternalServerError handles this case with default header values.

Internal server error
*/
type DeleteClientInternalServerError struct {
}

func (o *DeleteClientInternalServerError) Error() string {
	return fmt.Sprintf("[DELETE /client/{clientId}][%d] deleteClientInternalServerError ", 500)
}

func (o *DeleteClientInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
