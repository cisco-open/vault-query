// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// PostPolicySearchHandlerFunc turns a function with the right signature into a post policy search handler
type PostPolicySearchHandlerFunc func(PostPolicySearchParams) middleware.Responder

// Handle executing the request and returning a response
func (fn PostPolicySearchHandlerFunc) Handle(params PostPolicySearchParams) middleware.Responder {
	return fn(params)
}

// PostPolicySearchHandler interface for that can handle valid post policy search params
type PostPolicySearchHandler interface {
	Handle(PostPolicySearchParams) middleware.Responder
}

// NewPostPolicySearch creates a new http.Handler for the post policy search operation
func NewPostPolicySearch(ctx *middleware.Context, handler PostPolicySearchHandler) *PostPolicySearch {
	return &PostPolicySearch{Context: ctx, Handler: handler}
}

/*
	PostPolicySearch swagger:route POST /policy/search postPolicySearch

PostPolicySearch post policy search API
*/
type PostPolicySearch struct {
	Context *middleware.Context
	Handler PostPolicySearchHandler
}

func (o *PostPolicySearch) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewPostPolicySearchParams()
	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}

// PostPolicySearchBadRequestBody post policy search bad request body
//
// swagger:model PostPolicySearchBadRequestBody
type PostPolicySearchBadRequestBody struct {

	// id
	ID string `json:"id,omitempty"`

	// message
	Message string `json:"message,omitempty"`
}

// Validate validates this post policy search bad request body
func (o *PostPolicySearchBadRequestBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this post policy search bad request body based on context it is used
func (o *PostPolicySearchBadRequestBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostPolicySearchBadRequestBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostPolicySearchBadRequestBody) UnmarshalBinary(b []byte) error {
	var res PostPolicySearchBadRequestBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// PostPolicySearchBody post policy search body
//
// swagger:model PostPolicySearchBody
type PostPolicySearchBody struct {

	// path details
	PathDetails *PostPolicySearchParamsBodyPathDetails `json:"pathDetails,omitempty"`
}

// Validate validates this post policy search body
func (o *PostPolicySearchBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validatePathDetails(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *PostPolicySearchBody) validatePathDetails(formats strfmt.Registry) error {
	if swag.IsZero(o.PathDetails) { // not required
		return nil
	}

	if o.PathDetails != nil {
		if err := o.PathDetails.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("body" + "." + "pathDetails")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("body" + "." + "pathDetails")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this post policy search body based on the context it is used
func (o *PostPolicySearchBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := o.contextValidatePathDetails(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *PostPolicySearchBody) contextValidatePathDetails(ctx context.Context, formats strfmt.Registry) error {

	if o.PathDetails != nil {
		if err := o.PathDetails.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("body" + "." + "pathDetails")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("body" + "." + "pathDetails")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *PostPolicySearchBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostPolicySearchBody) UnmarshalBinary(b []byte) error {
	var res PostPolicySearchBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// PostPolicySearchInternalServerErrorBody post policy search internal server error body
//
// swagger:model PostPolicySearchInternalServerErrorBody
type PostPolicySearchInternalServerErrorBody struct {

	// id
	ID string `json:"id,omitempty"`
}

// Validate validates this post policy search internal server error body
func (o *PostPolicySearchInternalServerErrorBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this post policy search internal server error body based on context it is used
func (o *PostPolicySearchInternalServerErrorBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostPolicySearchInternalServerErrorBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostPolicySearchInternalServerErrorBody) UnmarshalBinary(b []byte) error {
	var res PostPolicySearchInternalServerErrorBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// PostPolicySearchOKBody post policy search o k body
//
// swagger:model PostPolicySearchOKBody
type PostPolicySearchOKBody struct {

	// The names of policy that may potentially allow the operation
	// Example: ["policy-a"]
	PolicyNames []string `json:"policyNames"`
}

// Validate validates this post policy search o k body
func (o *PostPolicySearchOKBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this post policy search o k body based on context it is used
func (o *PostPolicySearchOKBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostPolicySearchOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostPolicySearchOKBody) UnmarshalBinary(b []byte) error {
	var res PostPolicySearchOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// PostPolicySearchParamsBodyPathDetails post policy search params body path details
//
// swagger:model PostPolicySearchParamsBodyPathDetails
type PostPolicySearchParamsBodyPathDetails struct {

	// The namespace in which the path/query occurs
	// Example: meetpaas/mccdev
	Namespace string `json:"namespace,omitempty"`

	// The HTTP operation for the pqth
	// Example: create
	// Enum: [create read update patch delete list help alias-lookahead resolve-role revoke renew rollback]
	Op string `json:"op,omitempty"`

	// The vault path for the query
	// Example: secret/data/foo/bar
	Path string `json:"path,omitempty"`
}

// Validate validates this post policy search params body path details
func (o *PostPolicySearchParamsBodyPathDetails) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateOp(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var postPolicySearchParamsBodyPathDetailsTypeOpPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["create","read","update","patch","delete","list","help","alias-lookahead","resolve-role","revoke","renew","rollback"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		postPolicySearchParamsBodyPathDetailsTypeOpPropEnum = append(postPolicySearchParamsBodyPathDetailsTypeOpPropEnum, v)
	}
}

const (

	// PostPolicySearchParamsBodyPathDetailsOpCreate captures enum value "create"
	PostPolicySearchParamsBodyPathDetailsOpCreate string = "create"

	// PostPolicySearchParamsBodyPathDetailsOpRead captures enum value "read"
	PostPolicySearchParamsBodyPathDetailsOpRead string = "read"

	// PostPolicySearchParamsBodyPathDetailsOpUpdate captures enum value "update"
	PostPolicySearchParamsBodyPathDetailsOpUpdate string = "update"

	// PostPolicySearchParamsBodyPathDetailsOpPatch captures enum value "patch"
	PostPolicySearchParamsBodyPathDetailsOpPatch string = "patch"

	// PostPolicySearchParamsBodyPathDetailsOpDelete captures enum value "delete"
	PostPolicySearchParamsBodyPathDetailsOpDelete string = "delete"

	// PostPolicySearchParamsBodyPathDetailsOpList captures enum value "list"
	PostPolicySearchParamsBodyPathDetailsOpList string = "list"

	// PostPolicySearchParamsBodyPathDetailsOpHelp captures enum value "help"
	PostPolicySearchParamsBodyPathDetailsOpHelp string = "help"

	// PostPolicySearchParamsBodyPathDetailsOpAliasDashLookahead captures enum value "alias-lookahead"
	PostPolicySearchParamsBodyPathDetailsOpAliasDashLookahead string = "alias-lookahead"

	// PostPolicySearchParamsBodyPathDetailsOpResolveDashRole captures enum value "resolve-role"
	PostPolicySearchParamsBodyPathDetailsOpResolveDashRole string = "resolve-role"

	// PostPolicySearchParamsBodyPathDetailsOpRevoke captures enum value "revoke"
	PostPolicySearchParamsBodyPathDetailsOpRevoke string = "revoke"

	// PostPolicySearchParamsBodyPathDetailsOpRenew captures enum value "renew"
	PostPolicySearchParamsBodyPathDetailsOpRenew string = "renew"

	// PostPolicySearchParamsBodyPathDetailsOpRollback captures enum value "rollback"
	PostPolicySearchParamsBodyPathDetailsOpRollback string = "rollback"
)

// prop value enum
func (o *PostPolicySearchParamsBodyPathDetails) validateOpEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, postPolicySearchParamsBodyPathDetailsTypeOpPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (o *PostPolicySearchParamsBodyPathDetails) validateOp(formats strfmt.Registry) error {
	if swag.IsZero(o.Op) { // not required
		return nil
	}

	// value enum
	if err := o.validateOpEnum("body"+"."+"pathDetails"+"."+"op", "body", o.Op); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this post policy search params body path details based on context it is used
func (o *PostPolicySearchParamsBodyPathDetails) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostPolicySearchParamsBodyPathDetails) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostPolicySearchParamsBodyPathDetails) UnmarshalBinary(b []byte) error {
	var res PostPolicySearchParamsBodyPathDetails
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// PostPolicySearchUnauthorizedBody post policy search unauthorized body
//
// swagger:model PostPolicySearchUnauthorizedBody
type PostPolicySearchUnauthorizedBody struct {

	// id
	ID string `json:"id,omitempty"`
}

// Validate validates this post policy search unauthorized body
func (o *PostPolicySearchUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this post policy search unauthorized body based on context it is used
func (o *PostPolicySearchUnauthorizedBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PostPolicySearchUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostPolicySearchUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res PostPolicySearchUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}