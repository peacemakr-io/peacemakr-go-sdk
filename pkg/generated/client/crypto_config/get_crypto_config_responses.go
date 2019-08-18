// Code generated by go-swagger; DO NOT EDIT.

package crypto_config

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/notasecret/peacemakr-go-sdk/pkg/generated/models"
)

// GetCryptoConfigReader is a Reader for the GetCryptoConfig structure.
type GetCryptoConfigReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetCryptoConfigReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewGetCryptoConfigOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewGetCryptoConfigBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetCryptoConfigOK creates a GetCryptoConfigOK with default headers values
func NewGetCryptoConfigOK() *GetCryptoConfigOK {
	return &GetCryptoConfigOK{}
}

/*GetCryptoConfigOK handles this case with default header values.

Returns the requested configuration
*/
type GetCryptoConfigOK struct {
	Payload *models.CryptoConfig
}

func (o *GetCryptoConfigOK) Error() string {
	return fmt.Sprintf("[GET /crypto/config/{cryptoConfigId}][%d] getCryptoConfigOK  %+v", 200, o.Payload)
}

func (o *GetCryptoConfigOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.CryptoConfig)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCryptoConfigBadRequest creates a GetCryptoConfigBadRequest with default headers values
func NewGetCryptoConfigBadRequest() *GetCryptoConfigBadRequest {
	return &GetCryptoConfigBadRequest{}
}

/*GetCryptoConfigBadRequest handles this case with default header values.

Unable to process request
*/
type GetCryptoConfigBadRequest struct {
}

func (o *GetCryptoConfigBadRequest) Error() string {
	return fmt.Sprintf("[GET /crypto/config/{cryptoConfigId}][%d] getCryptoConfigBadRequest ", 400)
}

func (o *GetCryptoConfigBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
