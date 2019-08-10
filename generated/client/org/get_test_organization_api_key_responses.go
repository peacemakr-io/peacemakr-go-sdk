// Code generated by go-swagger; DO NOT EDIT.

package org

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/peacemakr-io/peacemakr-go-sdk/generated/models"
)

// GetTestOrganizationAPIKeyReader is a Reader for the GetTestOrganizationAPIKey structure.
type GetTestOrganizationAPIKeyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetTestOrganizationAPIKeyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewGetTestOrganizationAPIKeyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewGetTestOrganizationAPIKeyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 401:
		result := NewGetTestOrganizationAPIKeyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 500:
		result := NewGetTestOrganizationAPIKeyInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetTestOrganizationAPIKeyOK creates a GetTestOrganizationAPIKeyOK with default headers values
func NewGetTestOrganizationAPIKeyOK() *GetTestOrganizationAPIKeyOK {
	return &GetTestOrganizationAPIKeyOK{}
}

/*GetTestOrganizationAPIKeyOK handles this case with default header values.

Returns an apikey for a test org
*/
type GetTestOrganizationAPIKeyOK struct {
	Payload *models.APIKey
}

func (o *GetTestOrganizationAPIKeyOK) Error() string {
	return fmt.Sprintf("[GET /org/key/test][%d] getTestOrganizationApiKeyOK  %+v", 200, o.Payload)
}

func (o *GetTestOrganizationAPIKeyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIKey)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTestOrganizationAPIKeyBadRequest creates a GetTestOrganizationAPIKeyBadRequest with default headers values
func NewGetTestOrganizationAPIKeyBadRequest() *GetTestOrganizationAPIKeyBadRequest {
	return &GetTestOrganizationAPIKeyBadRequest{}
}

/*GetTestOrganizationAPIKeyBadRequest handles this case with default header values.

Unable to process request
*/
type GetTestOrganizationAPIKeyBadRequest struct {
}

func (o *GetTestOrganizationAPIKeyBadRequest) Error() string {
	return fmt.Sprintf("[GET /org/key/test][%d] getTestOrganizationApiKeyBadRequest ", 400)
}

func (o *GetTestOrganizationAPIKeyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetTestOrganizationAPIKeyUnauthorized creates a GetTestOrganizationAPIKeyUnauthorized with default headers values
func NewGetTestOrganizationAPIKeyUnauthorized() *GetTestOrganizationAPIKeyUnauthorized {
	return &GetTestOrganizationAPIKeyUnauthorized{}
}

/*GetTestOrganizationAPIKeyUnauthorized handles this case with default header values.

Not authenticated to perform request
*/
type GetTestOrganizationAPIKeyUnauthorized struct {
}

func (o *GetTestOrganizationAPIKeyUnauthorized) Error() string {
	return fmt.Sprintf("[GET /org/key/test][%d] getTestOrganizationApiKeyUnauthorized ", 401)
}

func (o *GetTestOrganizationAPIKeyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetTestOrganizationAPIKeyInternalServerError creates a GetTestOrganizationAPIKeyInternalServerError with default headers values
func NewGetTestOrganizationAPIKeyInternalServerError() *GetTestOrganizationAPIKeyInternalServerError {
	return &GetTestOrganizationAPIKeyInternalServerError{}
}

/*GetTestOrganizationAPIKeyInternalServerError handles this case with default header values.

Unrecoverable internal server error
*/
type GetTestOrganizationAPIKeyInternalServerError struct {
}

func (o *GetTestOrganizationAPIKeyInternalServerError) Error() string {
	return fmt.Sprintf("[GET /org/key/test][%d] getTestOrganizationApiKeyInternalServerError ", 500)
}

func (o *GetTestOrganizationAPIKeyInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
