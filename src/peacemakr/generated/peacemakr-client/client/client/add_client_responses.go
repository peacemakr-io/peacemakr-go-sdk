// Code generated by go-swagger; DO NOT EDIT.

package client

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "peacemakr/generated/peacemakr-client/models"
)

// AddClientReader is a Reader for the AddClient structure.
type AddClientReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AddClientReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewAddClientOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewAddClientBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewAddClientOK creates a AddClientOK with default headers values
func NewAddClientOK() *AddClientOK {
	return &AddClientOK{}
}

/*AddClientOK handles this case with default header values.

Successful registration of a new client.
*/
type AddClientOK struct {
	Payload *models.Client
}

func (o *AddClientOK) Error() string {
	return fmt.Sprintf("[POST /client][%d] addClientOK  %+v", 200, o.Payload)
}

func (o *AddClientOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Client)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAddClientBadRequest creates a AddClientBadRequest with default headers values
func NewAddClientBadRequest() *AddClientBadRequest {
	return &AddClientBadRequest{}
}

/*AddClientBadRequest handles this case with default header values.

Unable to process request
*/
type AddClientBadRequest struct {
}

func (o *AddClientBadRequest) Error() string {
	return fmt.Sprintf("[POST /client][%d] addClientBadRequest ", 400)
}

func (o *AddClientBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
