// Code generated by go-swagger; DO NOT EDIT.

package org

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/peacemakr-io/peacemakr-go-sdk/pkg/generated/models"
)

// GetOrganizationFromAPIKeyReader is a Reader for the GetOrganizationFromAPIKey structure.
type GetOrganizationFromAPIKeyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetOrganizationFromAPIKeyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewGetOrganizationFromAPIKeyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewGetOrganizationFromAPIKeyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 401:
		result := NewGetOrganizationFromAPIKeyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetOrganizationFromAPIKeyOK creates a GetOrganizationFromAPIKeyOK with default headers values
func NewGetOrganizationFromAPIKeyOK() *GetOrganizationFromAPIKeyOK {
	return &GetOrganizationFromAPIKeyOK{}
}

/*GetOrganizationFromAPIKeyOK handles this case with default header values.

Returns the Org requested
*/
type GetOrganizationFromAPIKeyOK struct {
	Payload *models.Organization
}

func (o *GetOrganizationFromAPIKeyOK) Error() string {
	return fmt.Sprintf("[GET /org/key/{apikey}][%d] getOrganizationFromApiKeyOK  %+v", 200, o.Payload)
}

func (o *GetOrganizationFromAPIKeyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Organization)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOrganizationFromAPIKeyBadRequest creates a GetOrganizationFromAPIKeyBadRequest with default headers values
func NewGetOrganizationFromAPIKeyBadRequest() *GetOrganizationFromAPIKeyBadRequest {
	return &GetOrganizationFromAPIKeyBadRequest{}
}

/*GetOrganizationFromAPIKeyBadRequest handles this case with default header values.

Unable to process request
*/
type GetOrganizationFromAPIKeyBadRequest struct {
}

func (o *GetOrganizationFromAPIKeyBadRequest) Error() string {
	return fmt.Sprintf("[GET /org/key/{apikey}][%d] getOrganizationFromApiKeyBadRequest ", 400)
}

func (o *GetOrganizationFromAPIKeyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetOrganizationFromAPIKeyUnauthorized creates a GetOrganizationFromAPIKeyUnauthorized with default headers values
func NewGetOrganizationFromAPIKeyUnauthorized() *GetOrganizationFromAPIKeyUnauthorized {
	return &GetOrganizationFromAPIKeyUnauthorized{}
}

/*GetOrganizationFromAPIKeyUnauthorized handles this case with default header values.

Not authenticated to perform request
*/
type GetOrganizationFromAPIKeyUnauthorized struct {
}

func (o *GetOrganizationFromAPIKeyUnauthorized) Error() string {
	return fmt.Sprintf("[GET /org/key/{apikey}][%d] getOrganizationFromApiKeyUnauthorized ", 401)
}

func (o *GetOrganizationFromAPIKeyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}