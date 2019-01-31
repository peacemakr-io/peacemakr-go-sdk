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

// SymmetricKeyUseDomain symmetric key use domain
// swagger:model SymmetricKeyUseDomain
type SymmetricKeyUseDomain struct {

	// creation time
	// Required: true
	CreationTime *int64 `json:"creationTime"`

	// after encrypting new plaintexts, package the ciphertext with this version of the packaged ciphertext
	// Required: true
	EncryptingPackagedCiphertextVersion *int64 `json:"encryptingPackagedCiphertextVersion"`

	// these are the semmetric key id's that belong to this use domain - these keys never belong to any other use domain
	// Required: true
	EncryptionKeyIds []string `json:"encryptionKeyIds"`

	// if all registered kds service become unreachable, then incoming requests for new and existing keys may fallback to the cloud provided KDS
	// Required: true
	EndableKDSFallbackToCloud *bool `json:"endableKDSFallbackToCloud"`

	// id
	// Required: true
	ID *string `json:"id"`

	// name
	Name string `json:"name,omitempty"`

	// the org id of the organization that owns these symmetric keys
	// Required: true
	OwnerOrgID *string `json:"ownerOrgId"`

	// number of seconds since key creation that the key will be available for decryption
	// Required: true
	SymmetricKeyDecryptionUseTTL *int64 `json:"symmetricKeyDecryptionUseTTL"`

	// the symmetric key derivation serivce id that can derive and wrap these keys
	// Required: true
	SymmetricKeyDerivationServiceID *string `json:"symmetricKeyDerivationServiceId"`

	// the specific encryption alg to encrypt new plaintexts for application layer encryption operations
	// Required: true
	SymmetricKeyEncryptionAlg *string `json:"symmetricKeyEncryptionAlg"`

	// number of seconds since key creation that the key will be available for encryption
	// Required: true
	SymmetricKeyEncryptionUseTTL *int64 `json:"symmetricKeyEncryptionUseTTL"`

	// number of seconds since key creation that the key will be available for encryption
	// Required: true
	SymmetricKeyInceptionTTL *int64 `json:"symmetricKeyInceptionTTL"`

	// the number of bits of all symmetric keys in this use domain
	// Required: true
	SymmetricKeyLength *int64 `json:"symmetricKeyLength"`

	// number of seconds since key creation that the key will be available for retention purposes
	// Required: true
	SymmetricKeyRetentionUseTTL *int64 `json:"symmetricKeyRetentionUseTTL"`
}

// Validate validates this symmetric key use domain
func (m *SymmetricKeyUseDomain) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreationTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEncryptingPackagedCiphertextVersion(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEncryptionKeyIds(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEndableKDSFallbackToCloud(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOwnerOrgID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSymmetricKeyDecryptionUseTTL(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSymmetricKeyDerivationServiceID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSymmetricKeyEncryptionAlg(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSymmetricKeyEncryptionUseTTL(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSymmetricKeyInceptionTTL(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSymmetricKeyLength(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSymmetricKeyRetentionUseTTL(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SymmetricKeyUseDomain) validateCreationTime(formats strfmt.Registry) error {

	if err := validate.Required("creationTime", "body", m.CreationTime); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyUseDomain) validateEncryptingPackagedCiphertextVersion(formats strfmt.Registry) error {

	if err := validate.Required("encryptingPackagedCiphertextVersion", "body", m.EncryptingPackagedCiphertextVersion); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyUseDomain) validateEncryptionKeyIds(formats strfmt.Registry) error {

	if err := validate.Required("encryptionKeyIds", "body", m.EncryptionKeyIds); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyUseDomain) validateEndableKDSFallbackToCloud(formats strfmt.Registry) error {

	if err := validate.Required("endableKDSFallbackToCloud", "body", m.EndableKDSFallbackToCloud); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyUseDomain) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyUseDomain) validateOwnerOrgID(formats strfmt.Registry) error {

	if err := validate.Required("ownerOrgId", "body", m.OwnerOrgID); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyUseDomain) validateSymmetricKeyDecryptionUseTTL(formats strfmt.Registry) error {

	if err := validate.Required("symmetricKeyDecryptionUseTTL", "body", m.SymmetricKeyDecryptionUseTTL); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyUseDomain) validateSymmetricKeyDerivationServiceID(formats strfmt.Registry) error {

	if err := validate.Required("symmetricKeyDerivationServiceId", "body", m.SymmetricKeyDerivationServiceID); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyUseDomain) validateSymmetricKeyEncryptionAlg(formats strfmt.Registry) error {

	if err := validate.Required("symmetricKeyEncryptionAlg", "body", m.SymmetricKeyEncryptionAlg); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyUseDomain) validateSymmetricKeyEncryptionUseTTL(formats strfmt.Registry) error {

	if err := validate.Required("symmetricKeyEncryptionUseTTL", "body", m.SymmetricKeyEncryptionUseTTL); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyUseDomain) validateSymmetricKeyInceptionTTL(formats strfmt.Registry) error {

	if err := validate.Required("symmetricKeyInceptionTTL", "body", m.SymmetricKeyInceptionTTL); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyUseDomain) validateSymmetricKeyLength(formats strfmt.Registry) error {

	if err := validate.Required("symmetricKeyLength", "body", m.SymmetricKeyLength); err != nil {
		return err
	}

	return nil
}

func (m *SymmetricKeyUseDomain) validateSymmetricKeyRetentionUseTTL(formats strfmt.Registry) error {

	if err := validate.Required("symmetricKeyRetentionUseTTL", "body", m.SymmetricKeyRetentionUseTTL); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *SymmetricKeyUseDomain) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SymmetricKeyUseDomain) UnmarshalBinary(b []byte) error {
	var res SymmetricKeyUseDomain
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
