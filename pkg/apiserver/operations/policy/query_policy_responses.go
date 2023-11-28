// Code generated by go-swagger; DO NOT EDIT.

package policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"vaultquery/models"
)

// QueryPolicyOKCode is the HTTP code returned for type QueryPolicyOK
const QueryPolicyOKCode int = 200

/*
QueryPolicyOK Successful query

swagger:response queryPolicyOK
*/
type QueryPolicyOK struct {

	/*
	  In: Body
	*/
	Payload *models.Response `json:"body,omitempty"`
}

// NewQueryPolicyOK creates QueryPolicyOK with default headers values
func NewQueryPolicyOK() *QueryPolicyOK {

	return &QueryPolicyOK{}
}

// WithPayload adds the payload to the query policy o k response
func (o *QueryPolicyOK) WithPayload(payload *models.Response) *QueryPolicyOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the query policy o k response
func (o *QueryPolicyOK) SetPayload(payload *models.Response) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *QueryPolicyOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// QueryPolicyBadRequestCode is the HTTP code returned for type QueryPolicyBadRequest
const QueryPolicyBadRequestCode int = 400

/*
QueryPolicyBadRequest Bad request

swagger:response queryPolicyBadRequest
*/
type QueryPolicyBadRequest struct {

	/*
	  In: Body
	*/
	Payload *QueryPolicyBadRequestBody `json:"body,omitempty"`
}

// NewQueryPolicyBadRequest creates QueryPolicyBadRequest with default headers values
func NewQueryPolicyBadRequest() *QueryPolicyBadRequest {

	return &QueryPolicyBadRequest{}
}

// WithPayload adds the payload to the query policy bad request response
func (o *QueryPolicyBadRequest) WithPayload(payload *QueryPolicyBadRequestBody) *QueryPolicyBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the query policy bad request response
func (o *QueryPolicyBadRequest) SetPayload(payload *QueryPolicyBadRequestBody) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *QueryPolicyBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// QueryPolicyUnauthorizedCode is the HTTP code returned for type QueryPolicyUnauthorized
const QueryPolicyUnauthorizedCode int = 401

/*
QueryPolicyUnauthorized Token accessor invalid/not enough permissions

swagger:response queryPolicyUnauthorized
*/
type QueryPolicyUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *QueryPolicyUnauthorizedBody `json:"body,omitempty"`
}

// NewQueryPolicyUnauthorized creates QueryPolicyUnauthorized with default headers values
func NewQueryPolicyUnauthorized() *QueryPolicyUnauthorized {

	return &QueryPolicyUnauthorized{}
}

// WithPayload adds the payload to the query policy unauthorized response
func (o *QueryPolicyUnauthorized) WithPayload(payload *QueryPolicyUnauthorizedBody) *QueryPolicyUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the query policy unauthorized response
func (o *QueryPolicyUnauthorized) SetPayload(payload *QueryPolicyUnauthorizedBody) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *QueryPolicyUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// QueryPolicyNotFoundCode is the HTTP code returned for type QueryPolicyNotFound
const QueryPolicyNotFoundCode int = 404

/*
QueryPolicyNotFound Policy not found

swagger:response queryPolicyNotFound
*/
type QueryPolicyNotFound struct {

	/*
	  In: Body
	*/
	Payload *QueryPolicyNotFoundBody `json:"body,omitempty"`
}

// NewQueryPolicyNotFound creates QueryPolicyNotFound with default headers values
func NewQueryPolicyNotFound() *QueryPolicyNotFound {

	return &QueryPolicyNotFound{}
}

// WithPayload adds the payload to the query policy not found response
func (o *QueryPolicyNotFound) WithPayload(payload *QueryPolicyNotFoundBody) *QueryPolicyNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the query policy not found response
func (o *QueryPolicyNotFound) SetPayload(payload *QueryPolicyNotFoundBody) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *QueryPolicyNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// QueryPolicyInternalServerErrorCode is the HTTP code returned for type QueryPolicyInternalServerError
const QueryPolicyInternalServerErrorCode int = 500

/*
QueryPolicyInternalServerError Internal error processing request

swagger:response queryPolicyInternalServerError
*/
type QueryPolicyInternalServerError struct {

	/*
	  In: Body
	*/
	Payload *QueryPolicyInternalServerErrorBody `json:"body,omitempty"`
}

// NewQueryPolicyInternalServerError creates QueryPolicyInternalServerError with default headers values
func NewQueryPolicyInternalServerError() *QueryPolicyInternalServerError {

	return &QueryPolicyInternalServerError{}
}

// WithPayload adds the payload to the query policy internal server error response
func (o *QueryPolicyInternalServerError) WithPayload(payload *QueryPolicyInternalServerErrorBody) *QueryPolicyInternalServerError {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the query policy internal server error response
func (o *QueryPolicyInternalServerError) SetPayload(payload *QueryPolicyInternalServerErrorBody) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *QueryPolicyInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}