// Code generated by go-swagger; DO NOT EDIT.

package key_derivation_service_registry

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/peacemakr-io/peacemakr-go-sdk/generated/models"
)

// GetAllSharedKeyDerivationServiceInstancesReader is a Reader for the GetAllSharedKeyDerivationServiceInstances structure.
type GetAllSharedKeyDerivationServiceInstancesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAllSharedKeyDerivationServiceInstancesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewGetAllSharedKeyDerivationServiceInstancesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewGetAllSharedKeyDerivationServiceInstancesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 401:
		result := NewGetAllSharedKeyDerivationServiceInstancesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 500:
		result := NewGetAllSharedKeyDerivationServiceInstancesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetAllSharedKeyDerivationServiceInstancesOK creates a GetAllSharedKeyDerivationServiceInstancesOK with default headers values
func NewGetAllSharedKeyDerivationServiceInstancesOK() *GetAllSharedKeyDerivationServiceInstancesOK {
	return &GetAllSharedKeyDerivationServiceInstancesOK{}
}

/*GetAllSharedKeyDerivationServiceInstancesOK handles this case with default header values.

Get all registered public key derivers - including shared cloud instances
*/
type GetAllSharedKeyDerivationServiceInstancesOK struct {
	Payload []*models.KeyDerivationInstance
}

func (o *GetAllSharedKeyDerivationServiceInstancesOK) Error() string {
	return fmt.Sprintf("[GET /crypto/deriver/all-shared-instances][%d] getAllSharedKeyDerivationServiceInstancesOK  %+v", 200, o.Payload)
}

func (o *GetAllSharedKeyDerivationServiceInstancesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAllSharedKeyDerivationServiceInstancesBadRequest creates a GetAllSharedKeyDerivationServiceInstancesBadRequest with default headers values
func NewGetAllSharedKeyDerivationServiceInstancesBadRequest() *GetAllSharedKeyDerivationServiceInstancesBadRequest {
	return &GetAllSharedKeyDerivationServiceInstancesBadRequest{}
}

/*GetAllSharedKeyDerivationServiceInstancesBadRequest handles this case with default header values.

Unable to process request.
*/
type GetAllSharedKeyDerivationServiceInstancesBadRequest struct {
}

func (o *GetAllSharedKeyDerivationServiceInstancesBadRequest) Error() string {
	return fmt.Sprintf("[GET /crypto/deriver/all-shared-instances][%d] getAllSharedKeyDerivationServiceInstancesBadRequest ", 400)
}

func (o *GetAllSharedKeyDerivationServiceInstancesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetAllSharedKeyDerivationServiceInstancesUnauthorized creates a GetAllSharedKeyDerivationServiceInstancesUnauthorized with default headers values
func NewGetAllSharedKeyDerivationServiceInstancesUnauthorized() *GetAllSharedKeyDerivationServiceInstancesUnauthorized {
	return &GetAllSharedKeyDerivationServiceInstancesUnauthorized{}
}

/*GetAllSharedKeyDerivationServiceInstancesUnauthorized handles this case with default header values.

Not Authenticated
*/
type GetAllSharedKeyDerivationServiceInstancesUnauthorized struct {
}

func (o *GetAllSharedKeyDerivationServiceInstancesUnauthorized) Error() string {
	return fmt.Sprintf("[GET /crypto/deriver/all-shared-instances][%d] getAllSharedKeyDerivationServiceInstancesUnauthorized ", 401)
}

func (o *GetAllSharedKeyDerivationServiceInstancesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetAllSharedKeyDerivationServiceInstancesInternalServerError creates a GetAllSharedKeyDerivationServiceInstancesInternalServerError with default headers values
func NewGetAllSharedKeyDerivationServiceInstancesInternalServerError() *GetAllSharedKeyDerivationServiceInstancesInternalServerError {
	return &GetAllSharedKeyDerivationServiceInstancesInternalServerError{}
}

/*GetAllSharedKeyDerivationServiceInstancesInternalServerError handles this case with default header values.

Unrecoverable internal server error
*/
type GetAllSharedKeyDerivationServiceInstancesInternalServerError struct {
}

func (o *GetAllSharedKeyDerivationServiceInstancesInternalServerError) Error() string {
	return fmt.Sprintf("[GET /crypto/deriver/all-shared-instances][%d] getAllSharedKeyDerivationServiceInstancesInternalServerError ", 500)
}

func (o *GetAllSharedKeyDerivationServiceInstancesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
