// Code generated by go-swagger; DO NOT EDIT.

package policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"context"
	"net/http"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// QueryPolicyHandlerFunc turns a function with the right signature into a query policy handler
type QueryPolicyHandlerFunc func(QueryPolicyParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn QueryPolicyHandlerFunc) Handle(params QueryPolicyParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// QueryPolicyHandler interface for that can handle valid query policy params
type QueryPolicyHandler interface {
	Handle(QueryPolicyParams, interface{}) middleware.Responder
}

// NewQueryPolicy creates a new http.Handler for the query policy operation
func NewQueryPolicy(ctx *middleware.Context, handler QueryPolicyHandler) *QueryPolicy {
	return &QueryPolicy{Context: ctx, Handler: handler}
}

/*
	QueryPolicy swagger:route POST /policy/query/allowed policy queryPolicy

Query if a path is allowed
*/
type QueryPolicy struct {
	Context *middleware.Context
	Handler QueryPolicyHandler
}

func (o *QueryPolicy) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewQueryPolicyParams()
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

// QueryPolicyBadRequestBody query policy bad request body
//
// swagger:model QueryPolicyBadRequestBody
type QueryPolicyBadRequestBody struct {

	// id
	ID string `json:"id,omitempty"`

	// message
	Message string `json:"message,omitempty"`
}

// Validate validates this query policy bad request body
func (o *QueryPolicyBadRequestBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this query policy bad request body based on context it is used
func (o *QueryPolicyBadRequestBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *QueryPolicyBadRequestBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *QueryPolicyBadRequestBody) UnmarshalBinary(b []byte) error {
	var res QueryPolicyBadRequestBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// QueryPolicyInternalServerErrorBody query policy internal server error body
//
// swagger:model QueryPolicyInternalServerErrorBody
type QueryPolicyInternalServerErrorBody struct {

	// id
	ID string `json:"id,omitempty"`
}

// Validate validates this query policy internal server error body
func (o *QueryPolicyInternalServerErrorBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this query policy internal server error body based on context it is used
func (o *QueryPolicyInternalServerErrorBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *QueryPolicyInternalServerErrorBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *QueryPolicyInternalServerErrorBody) UnmarshalBinary(b []byte) error {
	var res QueryPolicyInternalServerErrorBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// QueryPolicyNotFoundBody query policy not found body
//
// swagger:model QueryPolicyNotFoundBody
type QueryPolicyNotFoundBody struct {

	// id
	ID string `json:"id,omitempty"`
}

// Validate validates this query policy not found body
func (o *QueryPolicyNotFoundBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this query policy not found body based on context it is used
func (o *QueryPolicyNotFoundBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *QueryPolicyNotFoundBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *QueryPolicyNotFoundBody) UnmarshalBinary(b []byte) error {
	var res QueryPolicyNotFoundBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// QueryPolicyUnauthorizedBody query policy unauthorized body
//
// swagger:model QueryPolicyUnauthorizedBody
type QueryPolicyUnauthorizedBody struct {

	// id
	ID string `json:"id,omitempty"`

	// message
	Message string `json:"message,omitempty"`
}

// Validate validates this query policy unauthorized body
func (o *QueryPolicyUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this query policy unauthorized body based on context it is used
func (o *QueryPolicyUnauthorizedBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *QueryPolicyUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *QueryPolicyUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res QueryPolicyUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
