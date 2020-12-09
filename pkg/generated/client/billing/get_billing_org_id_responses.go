// Code generated by go-swagger; DO NOT EDIT.

package billing

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/peacemakr-io/peacemakr-go-sdk/pkg/generated/models"
)

// GetBillingOrgIDReader is a Reader for the GetBillingOrgID structure.
type GetBillingOrgIDReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetBillingOrgIDReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewGetBillingOrgIDOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewGetBillingOrgIDBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 401:
		result := NewGetBillingOrgIDUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 500:
		result := NewGetBillingOrgIDInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetBillingOrgIDOK creates a GetBillingOrgIDOK with default headers values
func NewGetBillingOrgIDOK() *GetBillingOrgIDOK {
	return &GetBillingOrgIDOK{}
}

/*GetBillingOrgIDOK handles this case with default header values.

Update successful
*/
type GetBillingOrgIDOK struct {
	Payload *models.PricingPlan
}

func (o *GetBillingOrgIDOK) Error() string {
	return fmt.Sprintf("[GET /billing/{orgId}][%d] getBillingOrgIdOK  %+v", 200, o.Payload)
}

func (o *GetBillingOrgIDOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PricingPlan)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetBillingOrgIDBadRequest creates a GetBillingOrgIDBadRequest with default headers values
func NewGetBillingOrgIDBadRequest() *GetBillingOrgIDBadRequest {
	return &GetBillingOrgIDBadRequest{}
}

/*GetBillingOrgIDBadRequest handles this case with default header values.

Unable to process request
*/
type GetBillingOrgIDBadRequest struct {
}

func (o *GetBillingOrgIDBadRequest) Error() string {
	return fmt.Sprintf("[GET /billing/{orgId}][%d] getBillingOrgIdBadRequest ", 400)
}

func (o *GetBillingOrgIDBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetBillingOrgIDUnauthorized creates a GetBillingOrgIDUnauthorized with default headers values
func NewGetBillingOrgIDUnauthorized() *GetBillingOrgIDUnauthorized {
	return &GetBillingOrgIDUnauthorized{}
}

/*GetBillingOrgIDUnauthorized handles this case with default header values.

Unauthorized request
*/
type GetBillingOrgIDUnauthorized struct {
}

func (o *GetBillingOrgIDUnauthorized) Error() string {
	return fmt.Sprintf("[GET /billing/{orgId}][%d] getBillingOrgIdUnauthorized ", 401)
}

func (o *GetBillingOrgIDUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetBillingOrgIDInternalServerError creates a GetBillingOrgIDInternalServerError with default headers values
func NewGetBillingOrgIDInternalServerError() *GetBillingOrgIDInternalServerError {
	return &GetBillingOrgIDInternalServerError{}
}

/*GetBillingOrgIDInternalServerError handles this case with default header values.

Internal server error
*/
type GetBillingOrgIDInternalServerError struct {
}

func (o *GetBillingOrgIDInternalServerError) Error() string {
	return fmt.Sprintf("[GET /billing/{orgId}][%d] getBillingOrgIdInternalServerError ", 500)
}

func (o *GetBillingOrgIDInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
