// Code generated by go-swagger; DO NOT EDIT.

package login

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/peacemakr-io/peacemakr-go-sdk/pkg/generated/models"
)

// LoginReader is a Reader for the Login structure.
type LoginReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *LoginReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewLoginOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	case 401:
		result := NewLoginUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	case 403:
		result := NewLoginForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewLoginOK creates a LoginOK with default headers values
func NewLoginOK() *LoginOK {
	return &LoginOK{}
}

/*LoginOK handles this case with default header values.

Returns a LoginResponse, which helps the calling client determine what screen to load next (create org vs current org).
*/
type LoginOK struct {
	Payload *models.LoginResponse
}

func (o *LoginOK) Error() string {
	return fmt.Sprintf("[GET /login][%d] loginOK  %+v", 200, o.Payload)
}

func (o *LoginOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.LoginResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewLoginUnauthorized creates a LoginUnauthorized with default headers values
func NewLoginUnauthorized() *LoginUnauthorized {
	return &LoginUnauthorized{}
}

/*LoginUnauthorized handles this case with default header values.

Not authenticated (user not who they say they are)
*/
type LoginUnauthorized struct {
}

func (o *LoginUnauthorized) Error() string {
	return fmt.Sprintf("[GET /login][%d] loginUnauthorized ", 401)
}

func (o *LoginUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewLoginForbidden creates a LoginForbidden with default headers values
func NewLoginForbidden() *LoginForbidden {
	return &LoginForbidden{}
}

/*LoginForbidden handles this case with default header values.

Not authorized (user not permitted to do that)
*/
type LoginForbidden struct {
}

func (o *LoginForbidden) Error() string {
	return fmt.Sprintf("[GET /login][%d] loginForbidden ", 403)
}

func (o *LoginForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
