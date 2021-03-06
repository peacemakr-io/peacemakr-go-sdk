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

// GetCloudOrganizationAPIKeyReader is a Reader for the GetCloudOrganizationAPIKey structure.
type GetCloudOrganizationAPIKeyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetCloudOrganizationAPIKeyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewGetCloudOrganizationAPIKeyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewGetCloudOrganizationAPIKeyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 401:
		result := NewGetCloudOrganizationAPIKeyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 403:
		result := NewGetCloudOrganizationAPIKeyForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 500:
		result := NewGetCloudOrganizationAPIKeyInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetCloudOrganizationAPIKeyOK creates a GetCloudOrganizationAPIKeyOK with default headers values
func NewGetCloudOrganizationAPIKeyOK() *GetCloudOrganizationAPIKeyOK {
	return &GetCloudOrganizationAPIKeyOK{}
}

/*GetCloudOrganizationAPIKeyOK handles this case with default header values.

Returns an apikey for a cloud org
*/
type GetCloudOrganizationAPIKeyOK struct {
	Payload *models.APIKey
}

func (o *GetCloudOrganizationAPIKeyOK) Error() string {
	return fmt.Sprintf("[GET /org/key/sharedCloud][%d] getCloudOrganizationApiKeyOK  %+v", 200, o.Payload)
}

func (o *GetCloudOrganizationAPIKeyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIKey)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetCloudOrganizationAPIKeyBadRequest creates a GetCloudOrganizationAPIKeyBadRequest with default headers values
func NewGetCloudOrganizationAPIKeyBadRequest() *GetCloudOrganizationAPIKeyBadRequest {
	return &GetCloudOrganizationAPIKeyBadRequest{}
}

/*GetCloudOrganizationAPIKeyBadRequest handles this case with default header values.

Unable to process request
*/
type GetCloudOrganizationAPIKeyBadRequest struct {
}

func (o *GetCloudOrganizationAPIKeyBadRequest) Error() string {
	return fmt.Sprintf("[GET /org/key/sharedCloud][%d] getCloudOrganizationApiKeyBadRequest ", 400)
}

func (o *GetCloudOrganizationAPIKeyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetCloudOrganizationAPIKeyUnauthorized creates a GetCloudOrganizationAPIKeyUnauthorized with default headers values
func NewGetCloudOrganizationAPIKeyUnauthorized() *GetCloudOrganizationAPIKeyUnauthorized {
	return &GetCloudOrganizationAPIKeyUnauthorized{}
}

/*GetCloudOrganizationAPIKeyUnauthorized handles this case with default header values.

Not authenticated to perform request
*/
type GetCloudOrganizationAPIKeyUnauthorized struct {
}

func (o *GetCloudOrganizationAPIKeyUnauthorized) Error() string {
	return fmt.Sprintf("[GET /org/key/sharedCloud][%d] getCloudOrganizationApiKeyUnauthorized ", 401)
}

func (o *GetCloudOrganizationAPIKeyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetCloudOrganizationAPIKeyForbidden creates a GetCloudOrganizationAPIKeyForbidden with default headers values
func NewGetCloudOrganizationAPIKeyForbidden() *GetCloudOrganizationAPIKeyForbidden {
	return &GetCloudOrganizationAPIKeyForbidden{}
}

/*GetCloudOrganizationAPIKeyForbidden handles this case with default header values.

Not authorized to perform request
*/
type GetCloudOrganizationAPIKeyForbidden struct {
}

func (o *GetCloudOrganizationAPIKeyForbidden) Error() string {
	return fmt.Sprintf("[GET /org/key/sharedCloud][%d] getCloudOrganizationApiKeyForbidden ", 403)
}

func (o *GetCloudOrganizationAPIKeyForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetCloudOrganizationAPIKeyInternalServerError creates a GetCloudOrganizationAPIKeyInternalServerError with default headers values
func NewGetCloudOrganizationAPIKeyInternalServerError() *GetCloudOrganizationAPIKeyInternalServerError {
	return &GetCloudOrganizationAPIKeyInternalServerError{}
}

/*GetCloudOrganizationAPIKeyInternalServerError handles this case with default header values.

Unrecoverable internal server error
*/
type GetCloudOrganizationAPIKeyInternalServerError struct {
}

func (o *GetCloudOrganizationAPIKeyInternalServerError) Error() string {
	return fmt.Sprintf("[GET /org/key/sharedCloud][%d] getCloudOrganizationApiKeyInternalServerError ", 500)
}

func (o *GetCloudOrganizationAPIKeyInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
