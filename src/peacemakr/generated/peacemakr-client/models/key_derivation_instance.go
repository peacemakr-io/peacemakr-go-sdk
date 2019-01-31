// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// KeyDerivationInstance key derivation instance
// swagger:model KeyDerivationInstance
type KeyDerivationInstance struct {

	// currently online and accepting requests for key derivation
	// Required: true
	Active *bool `json:"active"`

	// base URL from which this key deriver instance will respond to new key derivation job requests
	BaseURL string `json:"baseUrl,omitempty"`

	// instance id (concrete instance)
	// Required: true
	ID *string `json:"id"`

	// service id (virtual service id)
	// Required: true
	ServiceIds []string `json:"serviceIds"`

	// version
	// Required: true
	Version *string `json:"version"`
}

// Validate validates this key derivation instance
func (m *KeyDerivationInstance) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateActive(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateServiceIds(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVersion(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *KeyDerivationInstance) validateActive(formats strfmt.Registry) error {

	if err := validate.Required("active", "body", m.Active); err != nil {
		return err
	}

	return nil
}

func (m *KeyDerivationInstance) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *KeyDerivationInstance) validateServiceIds(formats strfmt.Registry) error {

	if err := validate.Required("serviceIds", "body", m.ServiceIds); err != nil {
		return err
	}

	return nil
}

func (m *KeyDerivationInstance) validateVersion(formats strfmt.Registry) error {

	if err := validate.Required("version", "body", m.Version); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *KeyDerivationInstance) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *KeyDerivationInstance) UnmarshalBinary(b []byte) error {
	var res KeyDerivationInstance
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
