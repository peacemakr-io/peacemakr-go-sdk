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

// SymmetricKeyRequest symmetric key request
// swagger:model SymmetricKeyRequest
type SymmetricKeyRequest struct {

	// Epoch time of the symmetric key requestion request time.
	// Required: true
	CreationTime *int64 `json:"creationTime"`

	// These are the keyId's to deliver all of the derived symmetric keys.
	// Required: true
	DeliveryPublicKeyIds []string `json:"deliveryPublicKeyIds"`

	// These are the keyId's of for the symmetric keys to actually derive.
	// Required: true
	DeriveSymmetricKeyIds []string `json:"deriveSymmetricKeyIds"`

	// Id of the symmetric key request.
	// Required: true
	ID *string `json:"id"`

	// The serviceId that must generate these keys.
	// Required: true
	KeyDerivationServiceID *string `json:"keyDerivationServiceId"`

	// If true the key deriver must sign delivered symmetric keys ciphertext blobs
	// Required: true
	MustSignDeliveredSymmetricKeys *bool `json:"mustSignDeliveredSymmetricKeys"`

	// After deriving symmetric keys, this determines the ciphertext packaging scheme required for encrypted key delivery.
	// Required: true
	PackagedCiphertextVersion *int64 `json:"packagedCiphertextVersion"`

	// Length in bytes of the derived symmetric keys.
	// Required: true
	SymmetricKeyLength *int64 `json:"symmetricKeyLength"`
}

// Validate validates this symmetric key request
func (m *SymmetricKeyRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreationTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDeliveryPublicKeyIds(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDeriveSymmetricKeyIds(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateKeyDerivationServiceID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMustSignDeliveredSymmetricKeys(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePackagedCiphertextVersion(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSymmetricKeyLength(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SymmetricKeyRequest) validateCreationTime(formats strfmt.Registry) error {

	if err := validate.Required("creationTime", "body", m.CreationTime); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyRequest) validateDeliveryPublicKeyIds(formats strfmt.Registry) error {

	if err := validate.Required("deliveryPublicKeyIds", "body", m.DeliveryPublicKeyIds); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyRequest) validateDeriveSymmetricKeyIds(formats strfmt.Registry) error {

	if err := validate.Required("deriveSymmetricKeyIds", "body", m.DeriveSymmetricKeyIds); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyRequest) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyRequest) validateKeyDerivationServiceID(formats strfmt.Registry) error {

	if err := validate.Required("keyDerivationServiceId", "body", m.KeyDerivationServiceID); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyRequest) validateMustSignDeliveredSymmetricKeys(formats strfmt.Registry) error {

	if err := validate.Required("mustSignDeliveredSymmetricKeys", "body", m.MustSignDeliveredSymmetricKeys); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyRequest) validatePackagedCiphertextVersion(formats strfmt.Registry) error {

	if err := validate.Required("packagedCiphertextVersion", "body", m.PackagedCiphertextVersion); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyRequest) validateSymmetricKeyLength(formats strfmt.Registry) error {

	if err := validate.Required("symmetricKeyLength", "body", m.SymmetricKeyLength); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *SymmetricKeyRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SymmetricKeyRequest) UnmarshalBinary(b []byte) error {
	var res SymmetricKeyRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
