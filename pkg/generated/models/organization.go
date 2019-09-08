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

// Organization organization
// swagger:model Organization
type Organization struct {

	// Array of api keys registered to this org
	// Required: true
	APIKeys []*APIKey `json:"apiKeys"`

	// Array of first 10 client id's registered to this org
	// Required: true
	ClientIds []string `json:"clientIds"`

	// contacts
	// Required: true
	Contacts []*Contact `json:"contacts"`

	// cryptoconfigId of this org
	// Required: true
	CryptoConfigID *string `json:"cryptoConfigId"`

	// id
	// Required: true
	ID *string `json:"id"`

	// name
	// Required: true
	Name *string `json:"name"`

	// Number of registered clients to this org
	NumberOfRegisteredClients int64 `json:"numberOfRegisteredClients,omitempty"`

	// Identifies the the customer in Stripe associated with this org
	// Required: true
	StripeCustomerID *string `json:"stripeCustomerId"`
}

// Validate validates this organization
func (m *Organization) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAPIKeys(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateClientIds(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateContacts(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCryptoConfigID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStripeCustomerID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Organization) validateAPIKeys(formats strfmt.Registry) error {

	if err := validate.Required("apiKeys", "body", m.APIKeys); err != nil {
		return err
	}

	for i := 0; i < len(m.APIKeys); i++ {
		if swag.IsZero(m.APIKeys[i]) { // not required
			continue
		}

		if m.APIKeys[i] != nil {
			if err := m.APIKeys[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("apiKeys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *Organization) validateClientIds(formats strfmt.Registry) error {

	if err := validate.Required("clientIds", "body", m.ClientIds); err != nil {
		return err
	}

	return nil
}

func (m *Organization) validateContacts(formats strfmt.Registry) error {

	if err := validate.Required("contacts", "body", m.Contacts); err != nil {
		return err
	}

	for i := 0; i < len(m.Contacts); i++ {
		if swag.IsZero(m.Contacts[i]) { // not required
			continue
		}

		if m.Contacts[i] != nil {
			if err := m.Contacts[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("contacts" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *Organization) validateCryptoConfigID(formats strfmt.Registry) error {

	if err := validate.Required("cryptoConfigId", "body", m.CryptoConfigID); err != nil {
		return err
	}

	return nil
}

func (m *Organization) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *Organization) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

func (m *Organization) validateStripeCustomerID(formats strfmt.Registry) error {

	if err := validate.Required("stripeCustomerId", "body", m.StripeCustomerID); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Organization) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Organization) UnmarshalBinary(b []byte) error {
	var res Organization
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
