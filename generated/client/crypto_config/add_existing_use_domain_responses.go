// Code generated by go-swagger; DO NOT EDIT.

package crypto_config

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"
)

// AddExistingUseDomainReader is a Reader for the AddExistingUseDomain structure.
type AddExistingUseDomainReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AddExistingUseDomainReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewAddExistingUseDomainOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewAddExistingUseDomainBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewAddExistingUseDomainOK creates a AddExistingUseDomainOK with default headers values
func NewAddExistingUseDomainOK() *AddExistingUseDomainOK {
	return &AddExistingUseDomainOK{}
}

/*AddExistingUseDomainOK handles this case with default header values.

Successfully add the existing use domain to the crypto config
*/
type AddExistingUseDomainOK struct {
}

func (o *AddExistingUseDomainOK) Error() string {
	return fmt.Sprintf("[POST /crypto/config/{cryptoConfigId}/useDomain/{useDomainId}][%d] addExistingUseDomainOK ", 200)
}

func (o *AddExistingUseDomainOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewAddExistingUseDomainBadRequest creates a AddExistingUseDomainBadRequest with default headers values
func NewAddExistingUseDomainBadRequest() *AddExistingUseDomainBadRequest {
	return &AddExistingUseDomainBadRequest{}
}

/*AddExistingUseDomainBadRequest handles this case with default header values.

Unable to process request
*/
type AddExistingUseDomainBadRequest struct {
}

func (o *AddExistingUseDomainBadRequest) Error() string {
	return fmt.Sprintf("[POST /crypto/config/{cryptoConfigId}/useDomain/{useDomainId}][%d] addExistingUseDomainBadRequest ", 400)
}

func (o *AddExistingUseDomainBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}