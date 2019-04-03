// Code generated by go-swagger; DO NOT EDIT.

package key_service

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/notasecret/peacemakr-go-sdk/generated/models"
)

// GetPublicKeyReader is a Reader for the GetPublicKey structure.
type GetPublicKeyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetPublicKeyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewGetPublicKeyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewGetPublicKeyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetPublicKeyOK creates a GetPublicKeyOK with default headers values
func NewGetPublicKeyOK() *GetPublicKeyOK {
	return &GetPublicKeyOK{}
}

/*GetPublicKeyOK handles this case with default header values.

Returns a public key in PEM format
*/
type GetPublicKeyOK struct {
	Payload *models.PublicKey
}

func (o *GetPublicKeyOK) Error() string {
	return fmt.Sprintf("[GET /crypto/asymmetric/{keyID}][%d] getPublicKeyOK  %+v", 200, o.Payload)
}

func (o *GetPublicKeyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PublicKey)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPublicKeyBadRequest creates a GetPublicKeyBadRequest with default headers values
func NewGetPublicKeyBadRequest() *GetPublicKeyBadRequest {
	return &GetPublicKeyBadRequest{}
}

/*GetPublicKeyBadRequest handles this case with default header values.

Unable to process request
*/
type GetPublicKeyBadRequest struct {
}

func (o *GetPublicKeyBadRequest) Error() string {
	return fmt.Sprintf("[GET /crypto/asymmetric/{keyID}][%d] getPublicKeyBadRequest ", 400)
}

func (o *GetPublicKeyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}