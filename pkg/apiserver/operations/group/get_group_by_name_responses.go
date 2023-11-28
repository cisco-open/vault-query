// Code generated by go-swagger; DO NOT EDIT.

package group

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// GetGroupByNameOKCode is the HTTP code returned for type GetGroupByNameOK
const GetGroupByNameOKCode int = 200

/*
GetGroupByNameOK successful operation

swagger:response getGroupByNameOK
*/
type GetGroupByNameOK struct {

	/*
	  In: Body
	*/
	Payload interface{} `json:"body,omitempty"`
}

// NewGetGroupByNameOK creates GetGroupByNameOK with default headers values
func NewGetGroupByNameOK() *GetGroupByNameOK {

	return &GetGroupByNameOK{}
}

// WithPayload adds the payload to the get group by name o k response
func (o *GetGroupByNameOK) WithPayload(payload interface{}) *GetGroupByNameOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get group by name o k response
func (o *GetGroupByNameOK) SetPayload(payload interface{}) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetGroupByNameOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}
}

// GetGroupByNameBadRequestCode is the HTTP code returned for type GetGroupByNameBadRequest
const GetGroupByNameBadRequestCode int = 400

/*
GetGroupByNameBadRequest Bad request

swagger:response getGroupByNameBadRequest
*/
type GetGroupByNameBadRequest struct {

	/*
	  In: Body
	*/
	Payload *GetGroupByNameBadRequestBody `json:"body,omitempty"`
}

// NewGetGroupByNameBadRequest creates GetGroupByNameBadRequest with default headers values
func NewGetGroupByNameBadRequest() *GetGroupByNameBadRequest {

	return &GetGroupByNameBadRequest{}
}

// WithPayload adds the payload to the get group by name bad request response
func (o *GetGroupByNameBadRequest) WithPayload(payload *GetGroupByNameBadRequestBody) *GetGroupByNameBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get group by name bad request response
func (o *GetGroupByNameBadRequest) SetPayload(payload *GetGroupByNameBadRequestBody) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetGroupByNameBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// GetGroupByNameUnauthorizedCode is the HTTP code returned for type GetGroupByNameUnauthorized
const GetGroupByNameUnauthorizedCode int = 401

/*
GetGroupByNameUnauthorized Token accessor invalid/not enough permissions

swagger:response getGroupByNameUnauthorized
*/
type GetGroupByNameUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *GetGroupByNameUnauthorizedBody `json:"body,omitempty"`
}

// NewGetGroupByNameUnauthorized creates GetGroupByNameUnauthorized with default headers values
func NewGetGroupByNameUnauthorized() *GetGroupByNameUnauthorized {

	return &GetGroupByNameUnauthorized{}
}

// WithPayload adds the payload to the get group by name unauthorized response
func (o *GetGroupByNameUnauthorized) WithPayload(payload *GetGroupByNameUnauthorizedBody) *GetGroupByNameUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get group by name unauthorized response
func (o *GetGroupByNameUnauthorized) SetPayload(payload *GetGroupByNameUnauthorizedBody) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetGroupByNameUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// GetGroupByNameNotFoundCode is the HTTP code returned for type GetGroupByNameNotFound
const GetGroupByNameNotFoundCode int = 404

/*
GetGroupByNameNotFound Group not found

swagger:response getGroupByNameNotFound
*/
type GetGroupByNameNotFound struct {

	/*
	  In: Body
	*/
	Payload *GetGroupByNameNotFoundBody `json:"body,omitempty"`
}

// NewGetGroupByNameNotFound creates GetGroupByNameNotFound with default headers values
func NewGetGroupByNameNotFound() *GetGroupByNameNotFound {

	return &GetGroupByNameNotFound{}
}

// WithPayload adds the payload to the get group by name not found response
func (o *GetGroupByNameNotFound) WithPayload(payload *GetGroupByNameNotFoundBody) *GetGroupByNameNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get group by name not found response
func (o *GetGroupByNameNotFound) SetPayload(payload *GetGroupByNameNotFoundBody) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetGroupByNameNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// GetGroupByNameInternalServerErrorCode is the HTTP code returned for type GetGroupByNameInternalServerError
const GetGroupByNameInternalServerErrorCode int = 500

/*
GetGroupByNameInternalServerError Internal error processing request

swagger:response getGroupByNameInternalServerError
*/
type GetGroupByNameInternalServerError struct {

	/*
	  In: Body
	*/
	Payload *GetGroupByNameInternalServerErrorBody `json:"body,omitempty"`
}

// NewGetGroupByNameInternalServerError creates GetGroupByNameInternalServerError with default headers values
func NewGetGroupByNameInternalServerError() *GetGroupByNameInternalServerError {

	return &GetGroupByNameInternalServerError{}
}

// WithPayload adds the payload to the get group by name internal server error response
func (o *GetGroupByNameInternalServerError) WithPayload(payload *GetGroupByNameInternalServerErrorBody) *GetGroupByNameInternalServerError {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get group by name internal server error response
func (o *GetGroupByNameInternalServerError) SetPayload(payload *GetGroupByNameInternalServerErrorBody) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetGroupByNameInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
