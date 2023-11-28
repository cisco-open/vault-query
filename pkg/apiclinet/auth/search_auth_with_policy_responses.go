// Code generated by go-swagger; DO NOT EDIT.

package auth

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"vaultquery/models"
)

// SearchAuthWithPolicyReader is a Reader for the SearchAuthWithPolicy structure.
type SearchAuthWithPolicyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SearchAuthWithPolicyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSearchAuthWithPolicyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewSearchAuthWithPolicyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewSearchAuthWithPolicyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSearchAuthWithPolicyNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewSearchAuthWithPolicyInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSearchAuthWithPolicyOK creates a SearchAuthWithPolicyOK with default headers values
func NewSearchAuthWithPolicyOK() *SearchAuthWithPolicyOK {
	return &SearchAuthWithPolicyOK{}
}

/*
SearchAuthWithPolicyOK describes a response with status code 200, with default header values.

successful operation
*/
type SearchAuthWithPolicyOK struct {
	Payload *SearchAuthWithPolicyOKBody
}

// IsSuccess returns true when this search auth with policy o k response has a 2xx status code
func (o *SearchAuthWithPolicyOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this search auth with policy o k response has a 3xx status code
func (o *SearchAuthWithPolicyOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this search auth with policy o k response has a 4xx status code
func (o *SearchAuthWithPolicyOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this search auth with policy o k response has a 5xx status code
func (o *SearchAuthWithPolicyOK) IsServerError() bool {
	return false
}

// IsCode returns true when this search auth with policy o k response a status code equal to that given
func (o *SearchAuthWithPolicyOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the search auth with policy o k response
func (o *SearchAuthWithPolicyOK) Code() int {
	return 200
}

func (o *SearchAuthWithPolicyOK) Error() string {
	return fmt.Sprintf("[GET /auth/search/policy][%d] searchAuthWithPolicyOK  %+v", 200, o.Payload)
}

func (o *SearchAuthWithPolicyOK) String() string {
	return fmt.Sprintf("[GET /auth/search/policy][%d] searchAuthWithPolicyOK  %+v", 200, o.Payload)
}

func (o *SearchAuthWithPolicyOK) GetPayload() *SearchAuthWithPolicyOKBody {
	return o.Payload
}

func (o *SearchAuthWithPolicyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SearchAuthWithPolicyOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSearchAuthWithPolicyBadRequest creates a SearchAuthWithPolicyBadRequest with default headers values
func NewSearchAuthWithPolicyBadRequest() *SearchAuthWithPolicyBadRequest {
	return &SearchAuthWithPolicyBadRequest{}
}

/*
SearchAuthWithPolicyBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type SearchAuthWithPolicyBadRequest struct {
	Payload *SearchAuthWithPolicyBadRequestBody
}

// IsSuccess returns true when this search auth with policy bad request response has a 2xx status code
func (o *SearchAuthWithPolicyBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this search auth with policy bad request response has a 3xx status code
func (o *SearchAuthWithPolicyBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this search auth with policy bad request response has a 4xx status code
func (o *SearchAuthWithPolicyBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this search auth with policy bad request response has a 5xx status code
func (o *SearchAuthWithPolicyBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this search auth with policy bad request response a status code equal to that given
func (o *SearchAuthWithPolicyBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the search auth with policy bad request response
func (o *SearchAuthWithPolicyBadRequest) Code() int {
	return 400
}

func (o *SearchAuthWithPolicyBadRequest) Error() string {
	return fmt.Sprintf("[GET /auth/search/policy][%d] searchAuthWithPolicyBadRequest  %+v", 400, o.Payload)
}

func (o *SearchAuthWithPolicyBadRequest) String() string {
	return fmt.Sprintf("[GET /auth/search/policy][%d] searchAuthWithPolicyBadRequest  %+v", 400, o.Payload)
}

func (o *SearchAuthWithPolicyBadRequest) GetPayload() *SearchAuthWithPolicyBadRequestBody {
	return o.Payload
}

func (o *SearchAuthWithPolicyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SearchAuthWithPolicyBadRequestBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSearchAuthWithPolicyUnauthorized creates a SearchAuthWithPolicyUnauthorized with default headers values
func NewSearchAuthWithPolicyUnauthorized() *SearchAuthWithPolicyUnauthorized {
	return &SearchAuthWithPolicyUnauthorized{}
}

/*
SearchAuthWithPolicyUnauthorized describes a response with status code 401, with default header values.

Token accessor invalid/not enough permissions
*/
type SearchAuthWithPolicyUnauthorized struct {
	Payload *SearchAuthWithPolicyUnauthorizedBody
}

// IsSuccess returns true when this search auth with policy unauthorized response has a 2xx status code
func (o *SearchAuthWithPolicyUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this search auth with policy unauthorized response has a 3xx status code
func (o *SearchAuthWithPolicyUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this search auth with policy unauthorized response has a 4xx status code
func (o *SearchAuthWithPolicyUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this search auth with policy unauthorized response has a 5xx status code
func (o *SearchAuthWithPolicyUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this search auth with policy unauthorized response a status code equal to that given
func (o *SearchAuthWithPolicyUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the search auth with policy unauthorized response
func (o *SearchAuthWithPolicyUnauthorized) Code() int {
	return 401
}

func (o *SearchAuthWithPolicyUnauthorized) Error() string {
	return fmt.Sprintf("[GET /auth/search/policy][%d] searchAuthWithPolicyUnauthorized  %+v", 401, o.Payload)
}

func (o *SearchAuthWithPolicyUnauthorized) String() string {
	return fmt.Sprintf("[GET /auth/search/policy][%d] searchAuthWithPolicyUnauthorized  %+v", 401, o.Payload)
}

func (o *SearchAuthWithPolicyUnauthorized) GetPayload() *SearchAuthWithPolicyUnauthorizedBody {
	return o.Payload
}

func (o *SearchAuthWithPolicyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SearchAuthWithPolicyUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSearchAuthWithPolicyNotFound creates a SearchAuthWithPolicyNotFound with default headers values
func NewSearchAuthWithPolicyNotFound() *SearchAuthWithPolicyNotFound {
	return &SearchAuthWithPolicyNotFound{}
}

/*
SearchAuthWithPolicyNotFound describes a response with status code 404, with default header values.

Policy not found
*/
type SearchAuthWithPolicyNotFound struct {
	Payload *SearchAuthWithPolicyNotFoundBody
}

// IsSuccess returns true when this search auth with policy not found response has a 2xx status code
func (o *SearchAuthWithPolicyNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this search auth with policy not found response has a 3xx status code
func (o *SearchAuthWithPolicyNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this search auth with policy not found response has a 4xx status code
func (o *SearchAuthWithPolicyNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this search auth with policy not found response has a 5xx status code
func (o *SearchAuthWithPolicyNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this search auth with policy not found response a status code equal to that given
func (o *SearchAuthWithPolicyNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the search auth with policy not found response
func (o *SearchAuthWithPolicyNotFound) Code() int {
	return 404
}

func (o *SearchAuthWithPolicyNotFound) Error() string {
	return fmt.Sprintf("[GET /auth/search/policy][%d] searchAuthWithPolicyNotFound  %+v", 404, o.Payload)
}

func (o *SearchAuthWithPolicyNotFound) String() string {
	return fmt.Sprintf("[GET /auth/search/policy][%d] searchAuthWithPolicyNotFound  %+v", 404, o.Payload)
}

func (o *SearchAuthWithPolicyNotFound) GetPayload() *SearchAuthWithPolicyNotFoundBody {
	return o.Payload
}

func (o *SearchAuthWithPolicyNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SearchAuthWithPolicyNotFoundBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSearchAuthWithPolicyInternalServerError creates a SearchAuthWithPolicyInternalServerError with default headers values
func NewSearchAuthWithPolicyInternalServerError() *SearchAuthWithPolicyInternalServerError {
	return &SearchAuthWithPolicyInternalServerError{}
}

/*
SearchAuthWithPolicyInternalServerError describes a response with status code 500, with default header values.

Internal error processing request
*/
type SearchAuthWithPolicyInternalServerError struct {
	Payload *SearchAuthWithPolicyInternalServerErrorBody
}

// IsSuccess returns true when this search auth with policy internal server error response has a 2xx status code
func (o *SearchAuthWithPolicyInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this search auth with policy internal server error response has a 3xx status code
func (o *SearchAuthWithPolicyInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this search auth with policy internal server error response has a 4xx status code
func (o *SearchAuthWithPolicyInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this search auth with policy internal server error response has a 5xx status code
func (o *SearchAuthWithPolicyInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this search auth with policy internal server error response a status code equal to that given
func (o *SearchAuthWithPolicyInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the search auth with policy internal server error response
func (o *SearchAuthWithPolicyInternalServerError) Code() int {
	return 500
}

func (o *SearchAuthWithPolicyInternalServerError) Error() string {
	return fmt.Sprintf("[GET /auth/search/policy][%d] searchAuthWithPolicyInternalServerError  %+v", 500, o.Payload)
}

func (o *SearchAuthWithPolicyInternalServerError) String() string {
	return fmt.Sprintf("[GET /auth/search/policy][%d] searchAuthWithPolicyInternalServerError  %+v", 500, o.Payload)
}

func (o *SearchAuthWithPolicyInternalServerError) GetPayload() *SearchAuthWithPolicyInternalServerErrorBody {
	return o.Payload
}

func (o *SearchAuthWithPolicyInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(SearchAuthWithPolicyInternalServerErrorBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*
SearchAuthWithPolicyBadRequestBody search auth with policy bad request body
swagger:model SearchAuthWithPolicyBadRequestBody
*/
type SearchAuthWithPolicyBadRequestBody struct {

	// id
	ID string `json:"id,omitempty"`

	// Human readable messages from the server
	Messages []*models.Message `json:"messages"`
}

// Validate validates this search auth with policy bad request body
func (o *SearchAuthWithPolicyBadRequestBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateMessages(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *SearchAuthWithPolicyBadRequestBody) validateMessages(formats strfmt.Registry) error {
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
					return ve.ValidateName("searchAuthWithPolicyBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("searchAuthWithPolicyBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this search auth with policy bad request body based on the context it is used
func (o *SearchAuthWithPolicyBadRequestBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := o.contextValidateMessages(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *SearchAuthWithPolicyBadRequestBody) contextValidateMessages(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(o.Messages); i++ {

		if o.Messages[i] != nil {
			if err := o.Messages[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("searchAuthWithPolicyBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("searchAuthWithPolicyBadRequest" + "." + "messages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *SearchAuthWithPolicyBadRequestBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SearchAuthWithPolicyBadRequestBody) UnmarshalBinary(b []byte) error {
	var res SearchAuthWithPolicyBadRequestBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*
SearchAuthWithPolicyInternalServerErrorBody search auth with policy internal server error body
swagger:model SearchAuthWithPolicyInternalServerErrorBody
*/
type SearchAuthWithPolicyInternalServerErrorBody struct {

	// id
	ID string `json:"id,omitempty"`
}

// Validate validates this search auth with policy internal server error body
func (o *SearchAuthWithPolicyInternalServerErrorBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this search auth with policy internal server error body based on context it is used
func (o *SearchAuthWithPolicyInternalServerErrorBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SearchAuthWithPolicyInternalServerErrorBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SearchAuthWithPolicyInternalServerErrorBody) UnmarshalBinary(b []byte) error {
	var res SearchAuthWithPolicyInternalServerErrorBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*
SearchAuthWithPolicyNotFoundBody search auth with policy not found body
swagger:model SearchAuthWithPolicyNotFoundBody
*/
type SearchAuthWithPolicyNotFoundBody struct {

	// id
	ID string `json:"id,omitempty"`
}

// Validate validates this search auth with policy not found body
func (o *SearchAuthWithPolicyNotFoundBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this search auth with policy not found body based on context it is used
func (o *SearchAuthWithPolicyNotFoundBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SearchAuthWithPolicyNotFoundBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SearchAuthWithPolicyNotFoundBody) UnmarshalBinary(b []byte) error {
	var res SearchAuthWithPolicyNotFoundBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*
SearchAuthWithPolicyOKBody search auth with policy o k body
swagger:model SearchAuthWithPolicyOKBody
*/
type SearchAuthWithPolicyOKBody struct {

	// The auth roles that have the policy
	AuthRoles map[string][]interface{} `json:"authRoles,omitempty"`

	// Human readable messages from the server
	Messages []*models.Message `json:"messages"`
}

// Validate validates this search auth with policy o k body
func (o *SearchAuthWithPolicyOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateMessages(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *SearchAuthWithPolicyOKBody) validateMessages(formats strfmt.Registry) error {
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
					return ve.ValidateName("searchAuthWithPolicyOK" + "." + "messages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("searchAuthWithPolicyOK" + "." + "messages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this search auth with policy o k body based on the context it is used
func (o *SearchAuthWithPolicyOKBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := o.contextValidateMessages(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *SearchAuthWithPolicyOKBody) contextValidateMessages(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(o.Messages); i++ {

		if o.Messages[i] != nil {
			if err := o.Messages[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("searchAuthWithPolicyOK" + "." + "messages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("searchAuthWithPolicyOK" + "." + "messages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (o *SearchAuthWithPolicyOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SearchAuthWithPolicyOKBody) UnmarshalBinary(b []byte) error {
	var res SearchAuthWithPolicyOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*
SearchAuthWithPolicyUnauthorizedBody search auth with policy unauthorized body
swagger:model SearchAuthWithPolicyUnauthorizedBody
*/
type SearchAuthWithPolicyUnauthorizedBody struct {

	// id
	ID string `json:"id,omitempty"`
}

// Validate validates this search auth with policy unauthorized body
func (o *SearchAuthWithPolicyUnauthorizedBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this search auth with policy unauthorized body based on context it is used
func (o *SearchAuthWithPolicyUnauthorizedBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *SearchAuthWithPolicyUnauthorizedBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *SearchAuthWithPolicyUnauthorizedBody) UnmarshalBinary(b []byte) error {
	var res SearchAuthWithPolicyUnauthorizedBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}