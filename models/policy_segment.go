// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// PolicySegment policy segment
//
// swagger:model PolicySegment
type PolicySegment struct {

	// name of the path segment
	Name string `json:"name,omitempty"`

	// raw policy segment (hcl or json)
	Raw string `json:"raw,omitempty"`
}

// Validate validates this policy segment
func (m *PolicySegment) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this policy segment based on context it is used
func (m *PolicySegment) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PolicySegment) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PolicySegment) UnmarshalBinary(b []byte) error {
	var res PolicySegment
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
