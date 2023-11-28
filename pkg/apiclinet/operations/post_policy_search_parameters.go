// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewPostPolicySearchParams creates a new PostPolicySearchParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPostPolicySearchParams() *PostPolicySearchParams {
	return &PostPolicySearchParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPostPolicySearchParamsWithTimeout creates a new PostPolicySearchParams object
// with the ability to set a timeout on a request.
func NewPostPolicySearchParamsWithTimeout(timeout time.Duration) *PostPolicySearchParams {
	return &PostPolicySearchParams{
		timeout: timeout,
	}
}

// NewPostPolicySearchParamsWithContext creates a new PostPolicySearchParams object
// with the ability to set a context for a request.
func NewPostPolicySearchParamsWithContext(ctx context.Context) *PostPolicySearchParams {
	return &PostPolicySearchParams{
		Context: ctx,
	}
}

// NewPostPolicySearchParamsWithHTTPClient creates a new PostPolicySearchParams object
// with the ability to set a custom HTTPClient for a request.
func NewPostPolicySearchParamsWithHTTPClient(client *http.Client) *PostPolicySearchParams {
	return &PostPolicySearchParams{
		HTTPClient: client,
	}
}

/*
PostPolicySearchParams contains all the parameters to send to the API endpoint

	for the post policy search operation.

	Typically these are written to a http.Request.
*/
type PostPolicySearchParams struct {

	// Body.
	Body PostPolicySearchBody

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the post policy search params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostPolicySearchParams) WithDefaults() *PostPolicySearchParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the post policy search params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostPolicySearchParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the post policy search params
func (o *PostPolicySearchParams) WithTimeout(timeout time.Duration) *PostPolicySearchParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the post policy search params
func (o *PostPolicySearchParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the post policy search params
func (o *PostPolicySearchParams) WithContext(ctx context.Context) *PostPolicySearchParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the post policy search params
func (o *PostPolicySearchParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the post policy search params
func (o *PostPolicySearchParams) WithHTTPClient(client *http.Client) *PostPolicySearchParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the post policy search params
func (o *PostPolicySearchParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the post policy search params
func (o *PostPolicySearchParams) WithBody(body PostPolicySearchBody) *PostPolicySearchParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the post policy search params
func (o *PostPolicySearchParams) SetBody(body PostPolicySearchBody) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PostPolicySearchParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if err := r.SetBodyParam(o.Body); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
