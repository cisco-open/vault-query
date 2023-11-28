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

// QueryPolicyAllowedHandlerFunc turns a function with the right signature into a query policy allowed handler
type QueryPolicyAllowedHandlerFunc func(QueryPolicyAllowedParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn QueryPolicyAllowedHandlerFunc) Handle(params QueryPolicyAllowedParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// QueryPolicyAllowedHandler interface for that can handle valid query policy allowed params
type QueryPolicyAllowedHandler interface {
	Handle(QueryPolicyAllowedParams, interface{}) middleware.Responder
}

// NewQueryPolicyAllowed creates a new http.Handler for the query policy allowed operation
func NewQueryPolicyAllowed(ctx *middleware.Context, handler QueryPolicyAllowedHandler) *QueryPolicyAllowed {
	return &QueryPolicyAllowed{Context: ctx, Handler: handler}
}

/*
	QueryPolicyAllowed swagger:route POST /policy/query/allowed policy queryPolicyAllowed

Query if a path is allowed
*/
type QueryPolicyAllowed struct {
	Context *middleware.Context
	Handler QueryPolicyAllowedHandler
}

func (o *QueryPolicyAllowed) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewQueryPolicyAllowedParams()
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

// QueryPolicyAllowedBadRequestBody query policy allowed bad request body
//
// swagger:model QueryPolicyAllowedBadRequestBody
type QueryPolicyAllowedBadRequestBody struct {

	// id
	ID string `json:"id,omitempty"`

	// Human readable messages from the server
	Messages []*models.Message `json:"messages"`
}

// Validate validates this query policy allowed bad request body
func (o *QueryPolicyAllowedBadRequestBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateMessages(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *QueryPolicyAllowedBadRequestBody) validateMessages(formats strfmt.Registry) error {
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
					return ve.ValidateName("queryPolicyAllowedBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("queryPolicyAllowedBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this query policy allowed bad request body based on the context it is used
func (o *QueryPolicyAllowedBadRequestBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := o.contextValidateMessages(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *QueryPolicyAllowedBadRequestBody) contextValidateMessages(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(o.Messages); i++ {

		if o.Messages[i] != nil {
			if err := o.Messages[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("queryPolicyAllowedBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("queryPolicyAllowedBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *QueryPolicyAllowedBadRequestBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *QueryPolicyAllowedBadRequestBody) UnmarshalBinary(b []byte) error {
	var res QueryPolicyAllowedBadRequestBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// QueryPolicyAllowedInternalServerErrorBody query policy allowed internal server error body
//
// swagger:model QueryPolicyAllowedInternalServerErrorBody
type QueryPolicyAllowedInternalServerErrorBody struct {

	// id
	ID string `json:"id,omitempty"`
}

// Validate validates this query policy allowed internal server error body
func (o *QueryPolicyAllowedInternalServerErrorBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this query policy allowed internal server error body based on context it is used
func (o *QueryPolicyAllowedInternalServerErrorBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *QueryPolicyAllowedInternalServerErrorBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *QueryPolicyAllowedInternalServerErrorBody) UnmarshalBinary(b []byte) error {
	var res QueryPolicyAllowedInternalServerErrorBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// QueryPolicyAllowedUnauthorizedBody query policy allowed unauthorized body
//
// swagger:model QueryPolicyAllowedUnauthorizedBody
type QueryPolicyAllowedUnauthorizedBody struct {

	// id
	ID string `json:"id,omitempty"`

	// message
	Message string `json:"message,omitempty"`
}

// Validate validates this query policy allowed unauthorized body
func (o *QueryPolicyAllowedUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this query policy allowed unauthorized body based on context it is used
func (o *QueryPolicyAllowedUnauthorizedBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *QueryPolicyAllowedUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *QueryPolicyAllowedUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res QueryPolicyAllowedUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}