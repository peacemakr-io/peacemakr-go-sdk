// Code generated by go-swagger; DO NOT EDIT.

package key_derivation_service_registry

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/peacemakr-io/peacemakr-go-sdk/pkg/generated/models"
)

// HeartbeatKeyDerivationServiceInstanceReader is a Reader for the HeartbeatKeyDerivationServiceInstance structure.
type HeartbeatKeyDerivationServiceInstanceReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *HeartbeatKeyDerivationServiceInstanceReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewHeartbeatKeyDerivationServiceInstanceOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewHeartbeatKeyDerivationServiceInstanceBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewHeartbeatKeyDerivationServiceInstanceOK creates a HeartbeatKeyDerivationServiceInstanceOK with default headers values
func NewHeartbeatKeyDerivationServiceInstanceOK() *HeartbeatKeyDerivationServiceInstanceOK {
	return &HeartbeatKeyDerivationServiceInstanceOK{}
}

/*HeartbeatKeyDerivationServiceInstanceOK handles this case with default header values.

Heatbeat accepted, possibly returning work
*/
type HeartbeatKeyDerivationServiceInstanceOK struct {
	Payload *models.HeatbeatResponse
}

func (o *HeartbeatKeyDerivationServiceInstanceOK) Error() string {
	return fmt.Sprintf("[GET /crypto/deriver/instance/{keyDerivationInstanceId}/heartbeat][%d] heartbeatKeyDerivationServiceInstanceOK  %+v", 200, o.Payload)
}

func (o *HeartbeatKeyDerivationServiceInstanceOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.HeatbeatResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewHeartbeatKeyDerivationServiceInstanceBadRequest creates a HeartbeatKeyDerivationServiceInstanceBadRequest with default headers values
func NewHeartbeatKeyDerivationServiceInstanceBadRequest() *HeartbeatKeyDerivationServiceInstanceBadRequest {
	return &HeartbeatKeyDerivationServiceInstanceBadRequest{}
}

/*HeartbeatKeyDerivationServiceInstanceBadRequest handles this case with default header values.

Unable to process request
*/
type HeartbeatKeyDerivationServiceInstanceBadRequest struct {
}

func (o *HeartbeatKeyDerivationServiceInstanceBadRequest) Error() string {
	return fmt.Sprintf("[GET /crypto/deriver/instance/{keyDerivationInstanceId}/heartbeat][%d] heartbeatKeyDerivationServiceInstanceBadRequest ", 400)
}

func (o *HeartbeatKeyDerivationServiceInstanceBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
