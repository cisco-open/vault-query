// Code generated by go-swagger; DO NOT EDIT.

package group

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

// SearchGroupWithPolicyHandlerFunc turns a function with the right signature into a search group with policy handler
type SearchGroupWithPolicyHandlerFunc func(SearchGroupWithPolicyParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn SearchGroupWithPolicyHandlerFunc) Handle(params SearchGroupWithPolicyParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// SearchGroupWithPolicyHandler interface for that can handle valid search group with policy params
type SearchGroupWithPolicyHandler interface {
	Handle(SearchGroupWithPolicyParams, interface{}) middleware.Responder
}

// NewSearchGroupWithPolicy creates a new http.Handler for the search group with policy operation
func NewSearchGroupWithPolicy(ctx *middleware.Context, handler SearchGroupWithPolicyHandler) *SearchGroupWithPolicy {
	return &SearchGroupWithPolicy{Context: ctx, Handler: handler}
}

/*
	SearchGroupWithPolicy swagger:route GET /group/search/policy group searchGroupWithPolicy

Search which groups have a policy
*/
type SearchGroupWithPolicy struct {
	Context *middleware.Context
	Handler SearchGroupWithPolicyHandler
}

func (o *SearchGroupWithPolicy) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewSearchGroupWithPolicyParams()
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

// SearchGroupWithPolicyBadRequestBody search group with policy bad request body
//
// swagger:model SearchGroupWithPolicyBadRequestBody
type SearchGroupWithPolicyBadRequestBody struct {

	// id
	ID string `json:"id,omitempty"`

	// Human readable messages from the server
	Messages []*models.Message `json:"messages"`
}

// Validate validates this search group with policy bad request body
func (o *SearchGroupWithPolicyBadRequestBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateMessages(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *SearchGroupWithPolicyBadRequestBody) validateMessages(formats strfmt.Registry) error {
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
					return ve.ValidateName("searchGroupWithPolicyBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("searchGroupWithPolicyBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this search group with policy bad request body based on the context it is used
func (o *SearchGroupWithPolicyBadRequestBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := o.contextValidateMessages(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *SearchGroupWithPolicyBadRequestBody) contextValidateMessages(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(o.Messages); i++ {

		if o.Messages[i] != nil {
			if err := o.Messages[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("searchGroupWithPolicyBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("searchGroupWithPolicyBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *SearchGroupWithPolicyBadRequestBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SearchGroupWithPolicyBadRequestBody) UnmarshalBinary(b []byte) error {
	var res SearchGroupWithPolicyBadRequestBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// SearchGroupWithPolicyInternalServerErrorBody search group with policy internal server error body
//
// swagger:model SearchGroupWithPolicyInternalServerErrorBody
type SearchGroupWithPolicyInternalServerErrorBody struct {

	// id
	ID string `json:"id,omitempty"`
}

// Validate validates this search group with policy internal server error body
func (o *SearchGroupWithPolicyInternalServerErrorBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this search group with policy internal server error body based on context it is used
func (o *SearchGroupWithPolicyInternalServerErrorBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SearchGroupWithPolicyInternalServerErrorBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SearchGroupWithPolicyInternalServerErrorBody) UnmarshalBinary(b []byte) error {
	var res SearchGroupWithPolicyInternalServerErrorBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// SearchGroupWithPolicyNotFoundBody search group with policy not found body
//
// swagger:model SearchGroupWithPolicyNotFoundBody
type SearchGroupWithPolicyNotFoundBody struct {

	// id
	ID string `json:"id,omitempty"`
}

// Validate validates this search group with policy not found body
func (o *SearchGroupWithPolicyNotFoundBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this search group with policy not found body based on context it is used
func (o *SearchGroupWithPolicyNotFoundBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SearchGroupWithPolicyNotFoundBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SearchGroupWithPolicyNotFoundBody) UnmarshalBinary(b []byte) error {
	var res SearchGroupWithPolicyNotFoundBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// SearchGroupWithPolicyOKBody search group with policy o k body
//
// swagger:model SearchGroupWithPolicyOKBody
type SearchGroupWithPolicyOKBody struct {

	// Any additional groups that might be related (such as parent or member groups)
	AdditionalGroups map[string]interface{} `json:"additionalGroups,omitempty"`

	// The groups that have the policy
	Groups map[string]interface{} `json:"groups,omitempty"`

	// Human readable messages from the server
	Messages []*models.Message `json:"messages"`
}

// Validate validates this search group with policy o k body
func (o *SearchGroupWithPolicyOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateMessages(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *SearchGroupWithPolicyOKBody) validateMessages(formats strfmt.Registry) error {
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
					return ve.ValidateName("searchGroupWithPolicyOK" + "." + "messages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("searchGroupWithPolicyOK" + "." + "messages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this search group with policy o k body based on the context it is used
func (o *SearchGroupWithPolicyOKBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := o.contextValidateMessages(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *SearchGroupWithPolicyOKBody) contextValidateMessages(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(o.Messages); i++ {

		if o.Messages[i] != nil {
			if err := o.Messages[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("searchGroupWithPolicyOK" + "." + "messages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("searchGroupWithPolicyOK" + "." + "messages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *SearchGroupWithPolicyOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SearchGroupWithPolicyOKBody) UnmarshalBinary(b []byte) error {
	var res SearchGroupWithPolicyOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// SearchGroupWithPolicyUnauthorizedBody search group with policy unauthorized body
//
// swagger:model SearchGroupWithPolicyUnauthorizedBody
type SearchGroupWithPolicyUnauthorizedBody struct {

	// id
	ID string `json:"id,omitempty"`
}

// Validate validates this search group with policy unauthorized body
func (o *SearchGroupWithPolicyUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this search group with policy unauthorized body based on context it is used
func (o *SearchGroupWithPolicyUnauthorizedBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SearchGroupWithPolicyUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SearchGroupWithPolicyUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res SearchGroupWithPolicyUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}