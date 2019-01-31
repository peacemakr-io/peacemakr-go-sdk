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

// GetClientReader is a Reader for the GetClient structure.
type GetClientReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetClientReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewGetClientOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewGetClientBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetClientOK creates a GetClientOK with default headers values
func NewGetClientOK() *GetClientOK {
	return &GetClientOK{}
}

/*GetClientOK handles this case with default header values.

Returns the client requested
*/
type GetClientOK struct {
	Payload *models.Client
}

func (o *GetClientOK) Error() string {
	return fmt.Sprintf("[GET /client/{clientId}][%d] getClientOK  %+v", 200, o.Payload)
}

func (o *GetClientOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Client)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetClientBadRequest creates a GetClientBadRequest with default headers values
func NewGetClientBadRequest() *GetClientBadRequest {
	return &GetClientBadRequest{}
}

/*GetClientBadRequest handles this case with default header values.

Unable to process request
*/
type GetClientBadRequest struct {
}

func (o *GetClientBadRequest) Error() string {
	return fmt.Sprintf("[GET /client/{clientId}][%d] getClientBadRequest ", 400)
}

func (o *GetClientBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
