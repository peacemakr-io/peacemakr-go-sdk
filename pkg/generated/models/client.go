// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"strconv"

	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// Client client
// swagger:model Client
type Client struct {

	// id
	// Required: true
	ID *string `json:"id"`

	// of all the public keys KeyDeriver's should deliver to this public key - it is also the most recently added public key
	PreferredPublicKeyID string `json:"preferredPublicKeyId,omitempty"`

	// public keys
	// Required: true
	PublicKeys []*PublicKey `json:"publicKeys"`

	// sdk
	Sdk string `json:"sdk,omitempty"`
}

// Validate validates this client
func (m *Client) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePublicKeys(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Client) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *Client) validatePublicKeys(formats strfmt.Registry) error {

	if err := validate.Required("publicKeys", "body", m.PublicKeys); err != nil {
		return err
	}

	for i := 0; i < len(m.PublicKeys); i++ {
		if swag.IsZero(m.PublicKeys[i]) { // not required
			continue
		}

		if m.PublicKeys[i] != nil {
			if err := m.PublicKeys[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("publicKeys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *Client) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Client) UnmarshalBinary(b []byte) error {
	var res Client
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
