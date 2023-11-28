// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// PostPolicySearchReader is a Reader for the PostPolicySearch structure.
type PostPolicySearchReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostPolicySearchReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPostPolicySearchOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostPolicySearchBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostPolicySearchUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostPolicySearchInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPostPolicySearchOK creates a PostPolicySearchOK with default headers values
func NewPostPolicySearchOK() *PostPolicySearchOK {
	return &PostPolicySearchOK{}
}

/*
PostPolicySearchOK describes a response with status code 200, with default header values.

successful operation
*/
type PostPolicySearchOK struct {
	Payload *PostPolicySearchOKBody
}

// IsSuccess returns true when this post policy search o k response has a 2xx status code
func (o *PostPolicySearchOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post policy search o k response has a 3xx status code
func (o *PostPolicySearchOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post policy search o k response has a 4xx status code
func (o *PostPolicySearchOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this post policy search o k response has a 5xx status code
func (o *PostPolicySearchOK) IsServerError() bool {
	return false
}

// IsCode returns true when this post policy search o k response a status code equal to that given
func (o *PostPolicySearchOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the post policy search o k response
func (o *PostPolicySearchOK) Code() int {
	return 200
}

func (o *PostPolicySearchOK) Error() string {
	return fmt.Sprintf("[POST /policy/search][%d] postPolicySearchOK  %+v", 200, o.Payload)
}

func (o *PostPolicySearchOK) String() string {
	return fmt.Sprintf("[POST /policy/search][%d] postPolicySearchOK  %+v", 200, o.Payload)
}

func (o *PostPolicySearchOK) GetPayload() *PostPolicySearchOKBody {
	return o.Payload
}

func (o *PostPolicySearchOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostPolicySearchOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostPolicySearchBadRequest creates a PostPolicySearchBadRequest with default headers values
func NewPostPolicySearchBadRequest() *PostPolicySearchBadRequest {
	return &PostPolicySearchBadRequest{}
}

/*
PostPolicySearchBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type PostPolicySearchBadRequest struct {
	Payload *PostPolicySearchBadRequestBody
}

// IsSuccess returns true when this post policy search bad request response has a 2xx status code
func (o *PostPolicySearchBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post policy search bad request response has a 3xx status code
func (o *PostPolicySearchBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post policy search bad request response has a 4xx status code
func (o *PostPolicySearchBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post policy search bad request response has a 5xx status code
func (o *PostPolicySearchBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post policy search bad request response a status code equal to that given
func (o *PostPolicySearchBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post policy search bad request response
func (o *PostPolicySearchBadRequest) Code() int {
	return 400
}

func (o *PostPolicySearchBadRequest) Error() string {
	return fmt.Sprintf("[POST /policy/search][%d] postPolicySearchBadRequest  %+v", 400, o.Payload)
}

func (o *PostPolicySearchBadRequest) String() string {
	return fmt.Sprintf("[POST /policy/search][%d] postPolicySearchBadRequest  %+v", 400, o.Payload)
}

func (o *PostPolicySearchBadRequest) GetPayload() *PostPolicySearchBadRequestBody {
	return o.Payload
}

func (o *PostPolicySearchBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostPolicySearchBadRequestBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostPolicySearchUnauthorized creates a PostPolicySearchUnauthorized with default headers values
func NewPostPolicySearchUnauthorized() *PostPolicySearchUnauthorized {
	return &PostPolicySearchUnauthorized{}
}

/*
PostPolicySearchUnauthorized describes a response with status code 401, with default header values.

Token accessor invalid/not enough permissions
*/
type PostPolicySearchUnauthorized struct {
	Payload *PostPolicySearchUnauthorizedBody
}

// IsSuccess returns true when this post policy search unauthorized response has a 2xx status code
func (o *PostPolicySearchUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post policy search unauthorized response has a 3xx status code
func (o *PostPolicySearchUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post policy search unauthorized response has a 4xx status code
func (o *PostPolicySearchUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post policy search unauthorized response has a 5xx status code
func (o *PostPolicySearchUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post policy search unauthorized response a status code equal to that given
func (o *PostPolicySearchUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post policy search unauthorized response
func (o *PostPolicySearchUnauthorized) Code() int {
	return 401
}

func (o *PostPolicySearchUnauthorized) Error() string {
	return fmt.Sprintf("[POST /policy/search][%d] postPolicySearchUnauthorized  %+v", 401, o.Payload)
}

func (o *PostPolicySearchUnauthorized) String() string {
	return fmt.Sprintf("[POST /policy/search][%d] postPolicySearchUnauthorized  %+v", 401, o.Payload)
}

func (o *PostPolicySearchUnauthorized) GetPayload() *PostPolicySearchUnauthorizedBody {
	return o.Payload
}

func (o *PostPolicySearchUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostPolicySearchUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostPolicySearchInternalServerError creates a PostPolicySearchInternalServerError with default headers values
func NewPostPolicySearchInternalServerError() *PostPolicySearchInternalServerError {
	return &PostPolicySearchInternalServerError{}
}

/*
PostPolicySearchInternalServerError describes a response with status code 500, with default header values.

Internal error processing request
*/
type PostPolicySearchInternalServerError struct {
	Payload *PostPolicySearchInternalServerErrorBody
}

// IsSuccess returns true when this post policy search internal server error response has a 2xx status code
func (o *PostPolicySearchInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post policy search internal server error response has a 3xx status code
func (o *PostPolicySearchInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post policy search internal server error response has a 4xx status code
func (o *PostPolicySearchInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post policy search internal server error response has a 5xx status code
func (o *PostPolicySearchInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post policy search internal server error response a status code equal to that given
func (o *PostPolicySearchInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post policy search internal server error response
func (o *PostPolicySearchInternalServerError) Code() int {
	return 500
}

func (o *PostPolicySearchInternalServerError) Error() string {
	return fmt.Sprintf("[POST /policy/search][%d] postPolicySearchInternalServerError  %+v", 500, o.Payload)
}

func (o *PostPolicySearchInternalServerError) String() string {
	return fmt.Sprintf("[POST /policy/search][%d] postPolicySearchInternalServerError  %+v", 500, o.Payload)
}

func (o *PostPolicySearchInternalServerError) GetPayload() *PostPolicySearchInternalServerErrorBody {
	return o.Payload
}

func (o *PostPolicySearchInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(PostPolicySearchInternalServerErrorBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*
PostPolicySearchBadRequestBody post policy search bad request body
swagger:model PostPolicySearchBadRequestBody
*/
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

/*
PostPolicySearchBody post policy search body
swagger:model PostPolicySearchBody
*/
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

/*
PostPolicySearchInternalServerErrorBody post policy search internal server error body
swagger:model PostPolicySearchInternalServerErrorBody
*/
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

/*
PostPolicySearchOKBody post policy search o k body
swagger:model PostPolicySearchOKBody
*/
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

/*
PostPolicySearchParamsBodyPathDetails post policy search params body path details
swagger:model PostPolicySearchParamsBodyPathDetails
*/
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

/*
PostPolicySearchUnauthorizedBody post policy search unauthorized body
swagger:model PostPolicySearchUnauthorizedBody
*/
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
