// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// Message message
//
// swagger:model Message
type Message struct {

	// msg body
	MsgBody string `json:"msgBody,omitempty"`

	// msg type
	// Enum: [info warn err]
	MsgType string `json:"msgType,omitempty"`
}

// Validate validates this message
func (m *Message) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateMsgType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var messageTypeMsgTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["info","warn","err"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		messageTypeMsgTypePropEnum = append(messageTypeMsgTypePropEnum, v)
	}
}

const (

	// MessageMsgTypeInfo captures enum value "info"
	MessageMsgTypeInfo string = "info"

	// MessageMsgTypeWarn captures enum value "warn"
	MessageMsgTypeWarn string = "warn"

	// MessageMsgTypeErr captures enum value "err"
	MessageMsgTypeErr string = "err"
)

// prop value enum
func (m *Message) validateMsgTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, messageTypeMsgTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *Message) validateMsgType(formats strfmt.Registry) error {
	if swag.IsZero(m.MsgType) { // not required
		return nil
	}

	// value enum
	if err := m.validateMsgTypeEnum("msgType", "body", m.MsgType); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this message based on context it is used
func (m *Message) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *Message) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Message) UnmarshalBinary(b []byte) error {
	var res Message
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
