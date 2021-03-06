// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/swag"
)

// PagedArray paged array
// swagger:model PagedArray
type PagedArray struct {

	// The current page's elements
	Elements []string `json:"elements"`

	// Current page of these elements
	PageNumber int64 `json:"pageNumber,omitempty"`

	// The max number of elements on a page
	PageSize int64 `json:"pageSize,omitempty"`
}

// Validate validates this paged array
func (m *PagedArray) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PagedArray) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PagedArray) UnmarshalBinary(b []byte) error {
	var res PagedArray
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
