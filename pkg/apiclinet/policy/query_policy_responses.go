// Code generated by go-swagger; DO NOT EDIT.

package policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"vaultquery/models"
)

// QueryPolicyReader is a Reader for the QueryPolicy structure.
type QueryPolicyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryPolicyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryPolicyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewQueryPolicyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewQueryPolicyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewQueryPolicyNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewQueryPolicyInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewQueryPolicyOK creates a QueryPolicyOK with default headers values
func NewQueryPolicyOK() *QueryPolicyOK {
	return &QueryPolicyOK{}
}

/*
QueryPolicyOK describes a response with status code 200, with default header values.

Successful query
*/
type QueryPolicyOK struct {
	Payload *models.Response
}

// IsSuccess returns true when this query policy o k response has a 2xx status code
func (o *QueryPolicyOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query policy o k response has a 3xx status code
func (o *QueryPolicyOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query policy o k response has a 4xx status code
func (o *QueryPolicyOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query policy o k response has a 5xx status code
func (o *QueryPolicyOK) IsServerError() bool {
	return false
}

// IsCode returns true when this query policy o k response a status code equal to that given
func (o *QueryPolicyOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query policy o k response
func (o *QueryPolicyOK) Code() int {
	return 200
}

func (o *QueryPolicyOK) Error() string {
	return fmt.Sprintf("[POST /policy/query/allowed][%d] queryPolicyOK  %+v", 200, o.Payload)
}

func (o *QueryPolicyOK) String() string {
	return fmt.Sprintf("[POST /policy/query/allowed][%d] queryPolicyOK  %+v", 200, o.Payload)
}

func (o *QueryPolicyOK) GetPayload() *models.Response {
	return o.Payload
}

func (o *QueryPolicyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Response)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryPolicyBadRequest creates a QueryPolicyBadRequest with default headers values
func NewQueryPolicyBadRequest() *QueryPolicyBadRequest {
	return &QueryPolicyBadRequest{}
}

/*
QueryPolicyBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type QueryPolicyBadRequest struct {
	Payload *QueryPolicyBadRequestBody
}

// IsSuccess returns true when this query policy bad request response has a 2xx status code
func (o *QueryPolicyBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query policy bad request response has a 3xx status code
func (o *QueryPolicyBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query policy bad request response has a 4xx status code
func (o *QueryPolicyBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this query policy bad request response has a 5xx status code
func (o *QueryPolicyBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this query policy bad request response a status code equal to that given
func (o *QueryPolicyBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the query policy bad request response
func (o *QueryPolicyBadRequest) Code() int {
	return 400
}

func (o *QueryPolicyBadRequest) Error() string {
	return fmt.Sprintf("[POST /policy/query/allowed][%d] queryPolicyBadRequest  %+v", 400, o.Payload)
}

func (o *QueryPolicyBadRequest) String() string {
	return fmt.Sprintf("[POST /policy/query/allowed][%d] queryPolicyBadRequest  %+v", 400, o.Payload)
}

func (o *QueryPolicyBadRequest) GetPayload() *QueryPolicyBadRequestBody {
	return o.Payload
}

func (o *QueryPolicyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(QueryPolicyBadRequestBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryPolicyUnauthorized creates a QueryPolicyUnauthorized with default headers values
func NewQueryPolicyUnauthorized() *QueryPolicyUnauthorized {
	return &QueryPolicyUnauthorized{}
}

/*
QueryPolicyUnauthorized describes a response with status code 401, with default header values.

Token accessor invalid/not enough permissions
*/
type QueryPolicyUnauthorized struct {
	Payload *QueryPolicyUnauthorizedBody
}

// IsSuccess returns true when this query policy unauthorized response has a 2xx status code
func (o *QueryPolicyUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query policy unauthorized response has a 3xx status code
func (o *QueryPolicyUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query policy unauthorized response has a 4xx status code
func (o *QueryPolicyUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this query policy unauthorized response has a 5xx status code
func (o *QueryPolicyUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this query policy unauthorized response a status code equal to that given
func (o *QueryPolicyUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the query policy unauthorized response
func (o *QueryPolicyUnauthorized) Code() int {
	return 401
}

func (o *QueryPolicyUnauthorized) Error() string {
	return fmt.Sprintf("[POST /policy/query/allowed][%d] queryPolicyUnauthorized  %+v", 401, o.Payload)
}

func (o *QueryPolicyUnauthorized) String() string {
	return fmt.Sprintf("[POST /policy/query/allowed][%d] queryPolicyUnauthorized  %+v", 401, o.Payload)
}

func (o *QueryPolicyUnauthorized) GetPayload() *QueryPolicyUnauthorizedBody {
	return o.Payload
}

func (o *QueryPolicyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(QueryPolicyUnauthorizedBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryPolicyNotFound creates a QueryPolicyNotFound with default headers values
func NewQueryPolicyNotFound() *QueryPolicyNotFound {
	return &QueryPolicyNotFound{}
}

/*
QueryPolicyNotFound describes a response with status code 404, with default header values.

Policy not found
*/
type QueryPolicyNotFound struct {
	Payload *QueryPolicyNotFoundBody
}

// IsSuccess returns true when this query policy not found response has a 2xx status code
func (o *QueryPolicyNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query policy not found response has a 3xx status code
func (o *QueryPolicyNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query policy not found response has a 4xx status code
func (o *QueryPolicyNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this query policy not found response has a 5xx status code
func (o *QueryPolicyNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this query policy not found response a status code equal to that given
func (o *QueryPolicyNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the query policy not found response
func (o *QueryPolicyNotFound) Code() int {
	return 404
}

func (o *QueryPolicyNotFound) Error() string {
	return fmt.Sprintf("[POST /policy/query/allowed][%d] queryPolicyNotFound  %+v", 404, o.Payload)
}

func (o *QueryPolicyNotFound) String() string {
	return fmt.Sprintf("[POST /policy/query/allowed][%d] queryPolicyNotFound  %+v", 404, o.Payload)
}

func (o *QueryPolicyNotFound) GetPayload() *QueryPolicyNotFoundBody {
	return o.Payload
}

func (o *QueryPolicyNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(QueryPolicyNotFoundBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQueryPolicyInternalServerError creates a QueryPolicyInternalServerError with default headers values
func NewQueryPolicyInternalServerError() *QueryPolicyInternalServerError {
	return &QueryPolicyInternalServerError{}
}

/*
QueryPolicyInternalServerError describes a response with status code 500, with default header values.

Internal error processing request
*/
type QueryPolicyInternalServerError struct {
	Payload *QueryPolicyInternalServerErrorBody
}

// IsSuccess returns true when this query policy internal server error response has a 2xx status code
func (o *QueryPolicyInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this query policy internal server error response has a 3xx status code
func (o *QueryPolicyInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query policy internal server error response has a 4xx status code
func (o *QueryPolicyInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this query policy internal server error response has a 5xx status code
func (o *QueryPolicyInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this query policy internal server error response a status code equal to that given
func (o *QueryPolicyInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the query policy internal server error response
func (o *QueryPolicyInternalServerError) Code() int {
	return 500
}

func (o *QueryPolicyInternalServerError) Error() string {
	return fmt.Sprintf("[POST /policy/query/allowed][%d] queryPolicyInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryPolicyInternalServerError) String() string {
	return fmt.Sprintf("[POST /policy/query/allowed][%d] queryPolicyInternalServerError  %+v", 500, o.Payload)
}

func (o *QueryPolicyInternalServerError) GetPayload() *QueryPolicyInternalServerErrorBody {
	return o.Payload
}

func (o *QueryPolicyInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(QueryPolicyInternalServerErrorBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*
QueryPolicyBadRequestBody query policy bad request body
swagger:model QueryPolicyBadRequestBody
*/
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

/*
QueryPolicyInternalServerErrorBody query policy internal server error body
swagger:model QueryPolicyInternalServerErrorBody
*/
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

/*
QueryPolicyNotFoundBody query policy not found body
swagger:model QueryPolicyNotFoundBody
*/
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

/*
QueryPolicyUnauthorizedBody query policy unauthorized body
swagger:model QueryPolicyUnauthorizedBody
*/
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