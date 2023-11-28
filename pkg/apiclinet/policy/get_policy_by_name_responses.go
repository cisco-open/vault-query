// Code generated by go-swagger; DO NOT EDIT.

package policy

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

// GetPolicyByNameReader is a Reader for the GetPolicyByName structure.
type GetPolicyByNameReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetPolicyByNameReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetPolicyByNameOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetPolicyByNameBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetPolicyByNameUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetPolicyByNameNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetPolicyByNameInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetPolicyByNameOK creates a GetPolicyByNameOK with default headers values
func NewGetPolicyByNameOK() *GetPolicyByNameOK {
	return &GetPolicyByNameOK{}
}

/*
GetPolicyByNameOK describes a response with status code 200, with default header values.

successful operation
*/
type GetPolicyByNameOK struct {
	Payload *GetPolicyByNameOKBody
}

// IsSuccess returns true when this get policy by name o k response has a 2xx status code
func (o *GetPolicyByNameOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get policy by name o k response has a 3xx status code
func (o *GetPolicyByNameOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get policy by name o k response has a 4xx status code
func (o *GetPolicyByNameOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get policy by name o k response has a 5xx status code
func (o *GetPolicyByNameOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get policy by name o k response a status code equal to that given
func (o *GetPolicyByNameOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get policy by name o k response
func (o *GetPolicyByNameOK) Code() int {
	return 200
}

func (o *GetPolicyByNameOK) Error() string {
	return fmt.Sprintf("[GET /policy/fetch/{policyName}][%d] getPolicyByNameOK  %+v", 200, o.Payload)
}

func (o *GetPolicyByNameOK) String() string {
	return fmt.Sprintf("[GET /policy/fetch/{policyName}][%d] getPolicyByNameOK  %+v", 200, o.Payload)
}

func (o *GetPolicyByNameOK) GetPayload() *GetPolicyByNameOKBody {
	return o.Payload
}

func (o *GetPolicyByNameOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetPolicyByNameOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPolicyByNameBadRequest creates a GetPolicyByNameBadRequest with default headers values
func NewGetPolicyByNameBadRequest() *GetPolicyByNameBadRequest {
	return &GetPolicyByNameBadRequest{}
}

/*
GetPolicyByNameBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type GetPolicyByNameBadRequest struct {
	Payload *GetPolicyByNameBadRequestBody
}

// IsSuccess returns true when this get policy by name bad request response has a 2xx status code
func (o *GetPolicyByNameBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get policy by name bad request response has a 3xx status code
func (o *GetPolicyByNameBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get policy by name bad request response has a 4xx status code
func (o *GetPolicyByNameBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get policy by name bad request response has a 5xx status code
func (o *GetPolicyByNameBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get policy by name bad request response a status code equal to that given
func (o *GetPolicyByNameBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get policy by name bad request response
func (o *GetPolicyByNameBadRequest) Code() int {
	return 400
}

func (o *GetPolicyByNameBadRequest) Error() string {
	return fmt.Sprintf("[GET /policy/fetch/{policyName}][%d] getPolicyByNameBadRequest  %+v", 400, o.Payload)
}

func (o *GetPolicyByNameBadRequest) String() string {
	return fmt.Sprintf("[GET /policy/fetch/{policyName}][%d] getPolicyByNameBadRequest  %+v", 400, o.Payload)
}

func (o *GetPolicyByNameBadRequest) GetPayload() *GetPolicyByNameBadRequestBody {
	return o.Payload
}

func (o *GetPolicyByNameBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetPolicyByNameBadRequestBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPolicyByNameUnauthorized creates a GetPolicyByNameUnauthorized with default headers values
func NewGetPolicyByNameUnauthorized() *GetPolicyByNameUnauthorized {
	return &GetPolicyByNameUnauthorized{}
}

/*
GetPolicyByNameUnauthorized describes a response with status code 401, with default header values.

Token accessor invalid/not enough permissions
*/
type GetPolicyByNameUnauthorized struct {
	Payload *GetPolicyByNameUnauthorizedBody
}

// IsSuccess returns true when this get policy by name unauthorized response has a 2xx status code
func (o *GetPolicyByNameUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get policy by name unauthorized response has a 3xx status code
func (o *GetPolicyByNameUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get policy by name unauthorized response has a 4xx status code
func (o *GetPolicyByNameUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get policy by name unauthorized response has a 5xx status code
func (o *GetPolicyByNameUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get policy by name unauthorized response a status code equal to that given
func (o *GetPolicyByNameUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get policy by name unauthorized response
func (o *GetPolicyByNameUnauthorized) Code() int {
	return 401
}

func (o *GetPolicyByNameUnauthorized) Error() string {
	return fmt.Sprintf("[GET /policy/fetch/{policyName}][%d] getPolicyByNameUnauthorized  %+v", 401, o.Payload)
}

func (o *GetPolicyByNameUnauthorized) String() string {
	return fmt.Sprintf("[GET /policy/fetch/{policyName}][%d] getPolicyByNameUnauthorized  %+v", 401, o.Payload)
}

func (o *GetPolicyByNameUnauthorized) GetPayload() *GetPolicyByNameUnauthorizedBody {
	return o.Payload
}

func (o *GetPolicyByNameUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetPolicyByNameUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPolicyByNameNotFound creates a GetPolicyByNameNotFound with default headers values
func NewGetPolicyByNameNotFound() *GetPolicyByNameNotFound {
	return &GetPolicyByNameNotFound{}
}

/*
GetPolicyByNameNotFound describes a response with status code 404, with default header values.

Policy not found
*/
type GetPolicyByNameNotFound struct {
	Payload *GetPolicyByNameNotFoundBody
}

// IsSuccess returns true when this get policy by name not found response has a 2xx status code
func (o *GetPolicyByNameNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get policy by name not found response has a 3xx status code
func (o *GetPolicyByNameNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get policy by name not found response has a 4xx status code
func (o *GetPolicyByNameNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get policy by name not found response has a 5xx status code
func (o *GetPolicyByNameNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get policy by name not found response a status code equal to that given
func (o *GetPolicyByNameNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get policy by name not found response
func (o *GetPolicyByNameNotFound) Code() int {
	return 404
}

func (o *GetPolicyByNameNotFound) Error() string {
	return fmt.Sprintf("[GET /policy/fetch/{policyName}][%d] getPolicyByNameNotFound  %+v", 404, o.Payload)
}

func (o *GetPolicyByNameNotFound) String() string {
	return fmt.Sprintf("[GET /policy/fetch/{policyName}][%d] getPolicyByNameNotFound  %+v", 404, o.Payload)
}

func (o *GetPolicyByNameNotFound) GetPayload() *GetPolicyByNameNotFoundBody {
	return o.Payload
}

func (o *GetPolicyByNameNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetPolicyByNameNotFoundBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPolicyByNameInternalServerError creates a GetPolicyByNameInternalServerError with default headers values
func NewGetPolicyByNameInternalServerError() *GetPolicyByNameInternalServerError {
	return &GetPolicyByNameInternalServerError{}
}

/*
GetPolicyByNameInternalServerError describes a response with status code 500, with default header values.

Internal error processing request
*/
type GetPolicyByNameInternalServerError struct {
	Payload *GetPolicyByNameInternalServerErrorBody
}

// IsSuccess returns true when this get policy by name internal server error response has a 2xx status code
func (o *GetPolicyByNameInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get policy by name internal server error response has a 3xx status code
func (o *GetPolicyByNameInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get policy by name internal server error response has a 4xx status code
func (o *GetPolicyByNameInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get policy by name internal server error response has a 5xx status code
func (o *GetPolicyByNameInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get policy by name internal server error response a status code equal to that given
func (o *GetPolicyByNameInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get policy by name internal server error response
func (o *GetPolicyByNameInternalServerError) Code() int {
	return 500
}

func (o *GetPolicyByNameInternalServerError) Error() string {
	return fmt.Sprintf("[GET /policy/fetch/{policyName}][%d] getPolicyByNameInternalServerError  %+v", 500, o.Payload)
}

func (o *GetPolicyByNameInternalServerError) String() string {
	return fmt.Sprintf("[GET /policy/fetch/{policyName}][%d] getPolicyByNameInternalServerError  %+v", 500, o.Payload)
}

func (o *GetPolicyByNameInternalServerError) GetPayload() *GetPolicyByNameInternalServerErrorBody {
	return o.Payload
}

func (o *GetPolicyByNameInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(GetPolicyByNameInternalServerErrorBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*
GetPolicyByNameBadRequestBody get policy by name bad request body
swagger:model GetPolicyByNameBadRequestBody
*/
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

/*
GetPolicyByNameInternalServerErrorBody get policy by name internal server error body
swagger:model GetPolicyByNameInternalServerErrorBody
*/
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

/*
GetPolicyByNameNotFoundBody get policy by name not found body
swagger:model GetPolicyByNameNotFoundBody
*/
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

/*
GetPolicyByNameOKBody get policy by name o k body
swagger:model GetPolicyByNameOKBody
*/
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

/*
GetPolicyByNameUnauthorizedBody get policy by name unauthorized body
swagger:model GetPolicyByNameUnauthorizedBody
*/
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