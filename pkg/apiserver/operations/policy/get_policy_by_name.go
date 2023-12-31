// Code generated by go-swagger; DO NOT EDIT.

package policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"context"
	"net/http"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"vaultquery/models"
)

// GetPolicyByNameHandlerFunc turns a function with the right signature into a get policy by name handler
type GetPolicyByNameHandlerFunc func(GetPolicyByNameParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn GetPolicyByNameHandlerFunc) Handle(params GetPolicyByNameParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// GetPolicyByNameHandler interface for that can handle valid get policy by name params
type GetPolicyByNameHandler interface {
	Handle(GetPolicyByNameParams, interface{}) middleware.Responder
}

// NewGetPolicyByName creates a new http.Handler for the get policy by name operation
func NewGetPolicyByName(ctx *middleware.Context, handler GetPolicyByNameHandler) *GetPolicyByName {
	return &GetPolicyByName{Context: ctx, Handler: handler}
}

/*
	GetPolicyByName swagger:route GET /policy/fetch/{policyName} policy getPolicyByName

# Find policy by name

Returns a policy string
*/
type GetPolicyByName struct {
	Context *middleware.Context
	Handler GetPolicyByNameHandler
}

func (o *GetPolicyByName) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewGetPolicyByNameParams()
	uprinc, aCtx, err := o.Context.Authorize(r, route)
	if err != nil {
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}
	if aCtx != nil {
		*r = *aCtx
	}
	var principal interface{}
	if uprinc != nil {
		principal = uprinc.(interface{}) // this is really a interface{}, I promise
	}

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params, principal) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}

// GetPolicyByNameBadRequestBody get policy by name bad request body
//
// swagger:model GetPolicyByNameBadRequestBody
type GetPolicyByNameBadRequestBody struct {

	// id
	ID string `json:"id,omitempty"`

	// Human readable messages from the server
	Messages []*models.Message `json:"messages"`
}

// Validate validates this get policy by name bad request body
func (o *GetPolicyByNameBadRequestBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateMessages(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetPolicyByNameBadRequestBody) validateMessages(formats strfmt.Registry) error {
	if swag.IsZero(o.Messages) { // not required
		return nil
	}

	for i := 0; i < len(o.Messages); i++ {
		if swag.IsZero(o.Messages[i]) { // not required
			continue
		}

		if o.Messages[i] != nil {
			if err := o.Messages[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("getPolicyByNameBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("getPolicyByNameBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this get policy by name bad request body based on the context it is used
func (o *GetPolicyByNameBadRequestBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := o.contextValidateMessages(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetPolicyByNameBadRequestBody) contextValidateMessages(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(o.Messages); i++ {

		if o.Messages[i] != nil {
			if err := o.Messages[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("getPolicyByNameBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("getPolicyByNameBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetPolicyByNameBadRequestBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetPolicyByNameBadRequestBody) UnmarshalBinary(b []byte) error {
	var res GetPolicyByNameBadRequestBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// GetPolicyByNameInternalServerErrorBody get policy by name internal server error body
//
// swagger:model GetPolicyByNameInternalServerErrorBody
type GetPolicyByNameInternalServerErrorBody struct {

	// id
	ID string `json:"id,omitempty"`
}

// Validate validates this get policy by name internal server error body
func (o *GetPolicyByNameInternalServerErrorBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this get policy by name internal server error body based on context it is used
func (o *GetPolicyByNameInternalServerErrorBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetPolicyByNameInternalServerErrorBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetPolicyByNameInternalServerErrorBody) UnmarshalBinary(b []byte) error {
	var res GetPolicyByNameInternalServerErrorBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// GetPolicyByNameNotFoundBody get policy by name not found body
//
// swagger:model GetPolicyByNameNotFoundBody
type GetPolicyByNameNotFoundBody struct {

	// id
	ID string `json:"id,omitempty"`
}

// Validate validates this get policy by name not found body
func (o *GetPolicyByNameNotFoundBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this get policy by name not found body based on context it is used
func (o *GetPolicyByNameNotFoundBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetPolicyByNameNotFoundBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetPolicyByNameNotFoundBody) UnmarshalBinary(b []byte) error {
	var res GetPolicyByNameNotFoundBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// GetPolicyByNameOKBody get policy by name o k body
//
// swagger:model GetPolicyByNameOKBody
type GetPolicyByNameOKBody struct {

	// Human readable messages from the server
	Messages []*models.Message `json:"messages"`

	// The name of policy
	// Example: policy-a
	PolicyName string `json:"policyName,omitempty"`

	// The raw policy as string
	PolicyRaw string `json:"policyRaw,omitempty"`
}

// Validate validates this get policy by name o k body
func (o *GetPolicyByNameOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateMessages(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetPolicyByNameOKBody) validateMessages(formats strfmt.Registry) error {
	if swag.IsZero(o.Messages) { // not required
		return nil
	}

	for i := 0; i < len(o.Messages); i++ {
		if swag.IsZero(o.Messages[i]) { // not required
			continue
		}

		if o.Messages[i] != nil {
			if err := o.Messages[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("getPolicyByNameOK" + "." + "messages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("getPolicyByNameOK" + "." + "messages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this get policy by name o k body based on the context it is used
func (o *GetPolicyByNameOKBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := o.contextValidateMessages(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetPolicyByNameOKBody) contextValidateMessages(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(o.Messages); i++ {

		if o.Messages[i] != nil {
			if err := o.Messages[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("getPolicyByNameOK" + "." + "messages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("getPolicyByNameOK" + "." + "messages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetPolicyByNameOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetPolicyByNameOKBody) UnmarshalBinary(b []byte) error {
	var res GetPolicyByNameOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// GetPolicyByNameUnauthorizedBody get policy by name unauthorized body
//
// swagger:model GetPolicyByNameUnauthorizedBody
type GetPolicyByNameUnauthorizedBody struct {

	// id
	ID string `json:"id,omitempty"`
}

// Validate validates this get policy by name unauthorized body
func (o *GetPolicyByNameUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this get policy by name unauthorized body based on context it is used
func (o *GetPolicyByNameUnauthorizedBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *GetPolicyByNameUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetPolicyByNameUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res GetPolicyByNameUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
