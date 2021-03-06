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

// AddOrganizationReader is a Reader for the AddOrganization structure.
type AddOrganizationReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AddOrganizationReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewAddOrganizationOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 400:
		result := NewAddOrganizationBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewAddOrganizationOK creates a AddOrganizationOK with default headers values
func NewAddOrganizationOK() *AddOrganizationOK {
	return &AddOrganizationOK{}
}

/*AddOrganizationOK handles this case with default header values.

Successful construction of an organization. Returns the actual organization which was registered. (Org includes an APIToken)
*/
type AddOrganizationOK struct {
	Payload *models.Organization
}

func (o *AddOrganizationOK) Error() string {
	return fmt.Sprintf("[POST /org][%d] addOrganizationOK  %+v", 200, o.Payload)
}

func (o *AddOrganizationOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Organization)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAddOrganizationBadRequest creates a AddOrganizationBadRequest with default headers values
func NewAddOrganizationBadRequest() *AddOrganizationBadRequest {
	return &AddOrganizationBadRequest{}
}

/*AddOrganizationBadRequest handles this case with default header values.

Unable to process request
*/
type AddOrganizationBadRequest struct {
}

func (o *AddOrganizationBadRequest) Error() string {
	return fmt.Sprintf("[POST /org][%d] addOrganizationBadRequest ", 400)
}

func (o *AddOrganizationBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
