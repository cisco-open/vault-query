// Code generated by go-swagger; DO NOT EDIT.

package policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"

	"vaultquery/models"
)

// SearchPolicyReader is a Reader for the SearchPolicy structure.
type SearchPolicyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SearchPolicyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSearchPolicyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewSearchPolicyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewSearchPolicyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewSearchPolicyInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSearchPolicyOK creates a SearchPolicyOK with default headers values
func NewSearchPolicyOK() *SearchPolicyOK {
	return &SearchPolicyOK{}
}

/*
SearchPolicyOK describes a response with status code 200, with default header values.

successful operation
*/
type SearchPolicyOK struct {
	Payload *SearchPolicyOKBody
}

// IsSuccess returns true when this search policy o k response has a 2xx status code
func (o *SearchPolicyOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this search policy o k response has a 3xx status code
func (o *SearchPolicyOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this search policy o k response has a 4xx status code
func (o *SearchPolicyOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this search policy o k response has a 5xx status code
func (o *SearchPolicyOK) IsServerError() bool {
	return false
}

// IsCode returns true when this search policy o k response a status code equal to that given
func (o *SearchPolicyOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the search policy o k response
func (o *SearchPolicyOK) Code() int {
	return 200
}

func (o *SearchPolicyOK) Error() string {
	return fmt.Sprintf("[POST /policy/search][%d] searchPolicyOK  %+v", 200, o.Payload)
}

func (o *SearchPolicyOK) String() string {
	return fmt.Sprintf("[POST /policy/search][%d] searchPolicyOK  %+v", 200, o.Payload)
}

func (o *SearchPolicyOK) GetPayload() *SearchPolicyOKBody {
	return o.Payload
}

func (o *SearchPolicyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SearchPolicyOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSearchPolicyBadRequest creates a SearchPolicyBadRequest with default headers values
func NewSearchPolicyBadRequest() *SearchPolicyBadRequest {
	return &SearchPolicyBadRequest{}
}

/*
SearchPolicyBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type SearchPolicyBadRequest struct {
	Payload *SearchPolicyBadRequestBody
}

// IsSuccess returns true when this search policy bad request response has a 2xx status code
func (o *SearchPolicyBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this search policy bad request response has a 3xx status code
func (o *SearchPolicyBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this search policy bad request response has a 4xx status code
func (o *SearchPolicyBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this search policy bad request response has a 5xx status code
func (o *SearchPolicyBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this search policy bad request response a status code equal to that given
func (o *SearchPolicyBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the search policy bad request response
func (o *SearchPolicyBadRequest) Code() int {
	return 400
}

func (o *SearchPolicyBadRequest) Error() string {
	return fmt.Sprintf("[POST /policy/search][%d] searchPolicyBadRequest  %+v", 400, o.Payload)
}

func (o *SearchPolicyBadRequest) String() string {
	return fmt.Sprintf("[POST /policy/search][%d] searchPolicyBadRequest  %+v", 400, o.Payload)
}

func (o *SearchPolicyBadRequest) GetPayload() *SearchPolicyBadRequestBody {
	return o.Payload
}

func (o *SearchPolicyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SearchPolicyBadRequestBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSearchPolicyUnauthorized creates a SearchPolicyUnauthorized with default headers values
func NewSearchPolicyUnauthorized() *SearchPolicyUnauthorized {
	return &SearchPolicyUnauthorized{}
}

/*
SearchPolicyUnauthorized describes a response with status code 401, with default header values.

Token accessor invalid/not enough permissions
*/
type SearchPolicyUnauthorized struct {
	Payload *SearchPolicyUnauthorizedBody
}

// IsSuccess returns true when this search policy unauthorized response has a 2xx status code
func (o *SearchPolicyUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this search policy unauthorized response has a 3xx status code
func (o *SearchPolicyUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this search policy unauthorized response has a 4xx status code
func (o *SearchPolicyUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this search policy unauthorized response has a 5xx status code
func (o *SearchPolicyUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this search policy unauthorized response a status code equal to that given
func (o *SearchPolicyUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the search policy unauthorized response
func (o *SearchPolicyUnauthorized) Code() int {
	return 401
}

func (o *SearchPolicyUnauthorized) Error() string {
	return fmt.Sprintf("[POST /policy/search][%d] searchPolicyUnauthorized  %+v", 401, o.Payload)
}

func (o *SearchPolicyUnauthorized) String() string {
	return fmt.Sprintf("[POST /policy/search][%d] searchPolicyUnauthorized  %+v", 401, o.Payload)
}

func (o *SearchPolicyUnauthorized) GetPayload() *SearchPolicyUnauthorizedBody {
	return o.Payload
}

func (o *SearchPolicyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SearchPolicyUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSearchPolicyInternalServerError creates a SearchPolicyInternalServerError with default headers values
func NewSearchPolicyInternalServerError() *SearchPolicyInternalServerError {
	return &SearchPolicyInternalServerError{}
}

/*
SearchPolicyInternalServerError describes a response with status code 500, with default header values.

Internal error processing request
*/
type SearchPolicyInternalServerError struct {
	Payload *SearchPolicyInternalServerErrorBody
}

// IsSuccess returns true when this search policy internal server error response has a 2xx status code
func (o *SearchPolicyInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this search policy internal server error response has a 3xx status code
func (o *SearchPolicyInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this search policy internal server error response has a 4xx status code
func (o *SearchPolicyInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this search policy internal server error response has a 5xx status code
func (o *SearchPolicyInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this search policy internal server error response a status code equal to that given
func (o *SearchPolicyInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the search policy internal server error response
func (o *SearchPolicyInternalServerError) Code() int {
	return 500
}

func (o *SearchPolicyInternalServerError) Error() string {
	return fmt.Sprintf("[POST /policy/search][%d] searchPolicyInternalServerError  %+v", 500, o.Payload)
}

func (o *SearchPolicyInternalServerError) String() string {
	return fmt.Sprintf("[POST /policy/search][%d] searchPolicyInternalServerError  %+v", 500, o.Payload)
}

func (o *SearchPolicyInternalServerError) GetPayload() *SearchPolicyInternalServerErrorBody {
	return o.Payload
}

func (o *SearchPolicyInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SearchPolicyInternalServerErrorBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*
SearchPolicyBadRequestBody search policy bad request body
swagger:model SearchPolicyBadRequestBody
*/
type SearchPolicyBadRequestBody struct {

	// id
	ID string `json:"id,omitempty"`

	// Human readable messages from the server
	Messages []*models.Message `json:"messages"`
}

// Validate validates this search policy bad request body
func (o *SearchPolicyBadRequestBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateMessages(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *SearchPolicyBadRequestBody) validateMessages(formats strfmt.Registry) error {
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
					return ve.ValidateName("searchPolicyBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("searchPolicyBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this search policy bad request body based on the context it is used
func (o *SearchPolicyBadRequestBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := o.contextValidateMessages(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *SearchPolicyBadRequestBody) contextValidateMessages(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(o.Messages); i++ {

		if o.Messages[i] != nil {
			if err := o.Messages[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("searchPolicyBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("searchPolicyBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *SearchPolicyBadRequestBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SearchPolicyBadRequestBody) UnmarshalBinary(b []byte) error {
	var res SearchPolicyBadRequestBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*
SearchPolicyBody search policy body
swagger:model SearchPolicyBody
*/
type SearchPolicyBody struct {

	// path details
	PathDetails *SearchPolicyParamsBodyPathDetails `json:"pathDetails,omitempty"`
}

// Validate validates this search policy body
func (o *SearchPolicyBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validatePathDetails(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *SearchPolicyBody) validatePathDetails(formats strfmt.Registry) error {
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

// ContextValidate validate this search policy body based on the context it is used
func (o *SearchPolicyBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := o.contextValidatePathDetails(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *SearchPolicyBody) contextValidatePathDetails(ctx context.Context, formats strfmt.Registry) error {

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
func (o *SearchPolicyBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SearchPolicyBody) UnmarshalBinary(b []byte) error {
	var res SearchPolicyBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*
SearchPolicyInternalServerErrorBody search policy internal server error body
swagger:model SearchPolicyInternalServerErrorBody
*/
type SearchPolicyInternalServerErrorBody struct {

	// id
	ID string `json:"id,omitempty"`
}

// Validate validates this search policy internal server error body
func (o *SearchPolicyInternalServerErrorBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this search policy internal server error body based on context it is used
func (o *SearchPolicyInternalServerErrorBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SearchPolicyInternalServerErrorBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SearchPolicyInternalServerErrorBody) UnmarshalBinary(b []byte) error {
	var res SearchPolicyInternalServerErrorBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*
SearchPolicyOKBody search policy o k body
swagger:model SearchPolicyOKBody
*/
type SearchPolicyOKBody struct {

	// denying policy segments
	DenyingPolicySegments map[string]map[string][]models.PolicySegment `json:"denyingPolicySegments,omitempty"`

	// granting policy segments
	GrantingPolicySegments map[string]map[string][]models.PolicySegment `json:"grantingPolicySegments,omitempty"`

	// Human readable messages from the server
	Messages []*models.Message `json:"messages"`
}

// Validate validates this search policy o k body
func (o *SearchPolicyOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateDenyingPolicySegments(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateGrantingPolicySegments(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateMessages(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *SearchPolicyOKBody) validateDenyingPolicySegments(formats strfmt.Registry) error {
	if swag.IsZero(o.DenyingPolicySegments) { // not required
		return nil
	}

	for k := range o.DenyingPolicySegments {

		for kk := range o.DenyingPolicySegments[k] {

			if err := validate.Required("searchPolicyOK"+"."+"denyingPolicySegments"+"."+k+"."+kk, "body", o.DenyingPolicySegments[k][kk]); err != nil {
				return err
			}

			for i := 0; i < len(o.DenyingPolicySegments[k][kk]); i++ {

				if err := o.DenyingPolicySegments[k][kk][i].Validate(formats); err != nil {
					if ve, ok := err.(*errors.Validation); ok {
						return ve.ValidateName("searchPolicyOK" + "." + "denyingPolicySegments" + "." + k + "." + kk + "." + strconv.Itoa(i))
					} else if ce, ok := err.(*errors.CompositeError); ok {
						return ce.ValidateName("searchPolicyOK" + "." + "denyingPolicySegments" + "." + k + "." + kk + "." + strconv.Itoa(i))
					}
					return err
				}

			}

		}

	}

	return nil
}

func (o *SearchPolicyOKBody) validateGrantingPolicySegments(formats strfmt.Registry) error {
	if swag.IsZero(o.GrantingPolicySegments) { // not required
		return nil
	}

	for k := range o.GrantingPolicySegments {

		for kk := range o.GrantingPolicySegments[k] {

			if err := validate.Required("searchPolicyOK"+"."+"grantingPolicySegments"+"."+k+"."+kk, "body", o.GrantingPolicySegments[k][kk]); err != nil {
				return err
			}

			for i := 0; i < len(o.GrantingPolicySegments[k][kk]); i++ {

				if err := o.GrantingPolicySegments[k][kk][i].Validate(formats); err != nil {
					if ve, ok := err.(*errors.Validation); ok {
						return ve.ValidateName("searchPolicyOK" + "." + "grantingPolicySegments" + "." + k + "." + kk + "." + strconv.Itoa(i))
					} else if ce, ok := err.(*errors.CompositeError); ok {
						return ce.ValidateName("searchPolicyOK" + "." + "grantingPolicySegments" + "." + k + "." + kk + "." + strconv.Itoa(i))
					}
					return err
				}

			}

		}

	}

	return nil
}

func (o *SearchPolicyOKBody) validateMessages(formats strfmt.Registry) error {
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
					return ve.ValidateName("searchPolicyOK" + "." + "messages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("searchPolicyOK" + "." + "messages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this search policy o k body based on the context it is used
func (o *SearchPolicyOKBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := o.contextValidateDenyingPolicySegments(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := o.contextValidateGrantingPolicySegments(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := o.contextValidateMessages(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *SearchPolicyOKBody) contextValidateDenyingPolicySegments(ctx context.Context, formats strfmt.Registry) error {

	for k := range o.DenyingPolicySegments {

		for kk := range o.DenyingPolicySegments[k] {

			for i := 0; i < len(o.DenyingPolicySegments[k][kk]); i++ {

				if err := o.DenyingPolicySegments[k][kk][i].ContextValidate(ctx, formats); err != nil {
					if ve, ok := err.(*errors.Validation); ok {
						return ve.ValidateName("searchPolicyOK" + "." + "denyingPolicySegments" + "." + k + "." + kk + "." + strconv.Itoa(i))
					} else if ce, ok := err.(*errors.CompositeError); ok {
						return ce.ValidateName("searchPolicyOK" + "." + "denyingPolicySegments" + "." + k + "." + kk + "." + strconv.Itoa(i))
					}
					return err
				}

			}

		}

	}

	return nil
}

func (o *SearchPolicyOKBody) contextValidateGrantingPolicySegments(ctx context.Context, formats strfmt.Registry) error {

	for k := range o.GrantingPolicySegments {

		for kk := range o.GrantingPolicySegments[k] {

			for i := 0; i < len(o.GrantingPolicySegments[k][kk]); i++ {

				if err := o.GrantingPolicySegments[k][kk][i].ContextValidate(ctx, formats); err != nil {
					if ve, ok := err.(*errors.Validation); ok {
						return ve.ValidateName("searchPolicyOK" + "." + "grantingPolicySegments" + "." + k + "." + kk + "." + strconv.Itoa(i))
					} else if ce, ok := err.(*errors.CompositeError); ok {
						return ce.ValidateName("searchPolicyOK" + "." + "grantingPolicySegments" + "." + k + "." + kk + "." + strconv.Itoa(i))
					}
					return err
				}

			}

		}

	}

	return nil
}

func (o *SearchPolicyOKBody) contextValidateMessages(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(o.Messages); i++ {

		if o.Messages[i] != nil {
			if err := o.Messages[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("searchPolicyOK" + "." + "messages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("searchPolicyOK" + "." + "messages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *SearchPolicyOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SearchPolicyOKBody) UnmarshalBinary(b []byte) error {
	var res SearchPolicyOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*
SearchPolicyParamsBodyPathDetails search policy params body path details
swagger:model SearchPolicyParamsBodyPathDetails
*/
type SearchPolicyParamsBodyPathDetails struct {

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

// Validate validates this search policy params body path details
func (o *SearchPolicyParamsBodyPathDetails) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateOp(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var searchPolicyParamsBodyPathDetailsTypeOpPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["create","read","update","patch","delete","list","help","alias-lookahead","resolve-role","revoke","renew","rollback"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		searchPolicyParamsBodyPathDetailsTypeOpPropEnum = append(searchPolicyParamsBodyPathDetailsTypeOpPropEnum, v)
	}
}

const (

	// SearchPolicyParamsBodyPathDetailsOpCreate captures enum value "create"
	SearchPolicyParamsBodyPathDetailsOpCreate string = "create"

	// SearchPolicyParamsBodyPathDetailsOpRead captures enum value "read"
	SearchPolicyParamsBodyPathDetailsOpRead string = "read"

	// SearchPolicyParamsBodyPathDetailsOpUpdate captures enum value "update"
	SearchPolicyParamsBodyPathDetailsOpUpdate string = "update"

	// SearchPolicyParamsBodyPathDetailsOpPatch captures enum value "patch"
	SearchPolicyParamsBodyPathDetailsOpPatch string = "patch"

	// SearchPolicyParamsBodyPathDetailsOpDelete captures enum value "delete"
	SearchPolicyParamsBodyPathDetailsOpDelete string = "delete"

	// SearchPolicyParamsBodyPathDetailsOpList captures enum value "list"
	SearchPolicyParamsBodyPathDetailsOpList string = "list"

	// SearchPolicyParamsBodyPathDetailsOpHelp captures enum value "help"
	SearchPolicyParamsBodyPathDetailsOpHelp string = "help"

	// SearchPolicyParamsBodyPathDetailsOpAliasDashLookahead captures enum value "alias-lookahead"
	SearchPolicyParamsBodyPathDetailsOpAliasDashLookahead string = "alias-lookahead"

	// SearchPolicyParamsBodyPathDetailsOpResolveDashRole captures enum value "resolve-role"
	SearchPolicyParamsBodyPathDetailsOpResolveDashRole string = "resolve-role"

	// SearchPolicyParamsBodyPathDetailsOpRevoke captures enum value "revoke"
	SearchPolicyParamsBodyPathDetailsOpRevoke string = "revoke"

	// SearchPolicyParamsBodyPathDetailsOpRenew captures enum value "renew"
	SearchPolicyParamsBodyPathDetailsOpRenew string = "renew"

	// SearchPolicyParamsBodyPathDetailsOpRollback captures enum value "rollback"
	SearchPolicyParamsBodyPathDetailsOpRollback string = "rollback"
)

// prop value enum
func (o *SearchPolicyParamsBodyPathDetails) validateOpEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, searchPolicyParamsBodyPathDetailsTypeOpPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (o *SearchPolicyParamsBodyPathDetails) validateOp(formats strfmt.Registry) error {
	if swag.IsZero(o.Op) { // not required
		return nil
	}

	// value enum
	if err := o.validateOpEnum("body"+"."+"pathDetails"+"."+"op", "body", o.Op); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this search policy params body path details based on context it is used
func (o *SearchPolicyParamsBodyPathDetails) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SearchPolicyParamsBodyPathDetails) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SearchPolicyParamsBodyPathDetails) UnmarshalBinary(b []byte) error {
	var res SearchPolicyParamsBodyPathDetails
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*
SearchPolicyUnauthorizedBody search policy unauthorized body
swagger:model SearchPolicyUnauthorizedBody
*/
type SearchPolicyUnauthorizedBody struct {

	// id
	ID string `json:"id,omitempty"`
}

// Validate validates this search policy unauthorized body
func (o *SearchPolicyUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this search policy unauthorized body based on context it is used
func (o *SearchPolicyUnauthorizedBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SearchPolicyUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SearchPolicyUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res SearchPolicyUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}