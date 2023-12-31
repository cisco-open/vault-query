// Code generated by go-swagger; DO NOT EDIT.

package policy

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

	"vaultquery/models"
)

// NewQueryPolicyAllowedParams creates a new QueryPolicyAllowedParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewQueryPolicyAllowedParams() *QueryPolicyAllowedParams {
	return &QueryPolicyAllowedParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewQueryPolicyAllowedParamsWithTimeout creates a new QueryPolicyAllowedParams object
// with the ability to set a timeout on a request.
func NewQueryPolicyAllowedParamsWithTimeout(timeout time.Duration) *QueryPolicyAllowedParams {
	return &QueryPolicyAllowedParams{
		timeout: timeout,
	}
}

// NewQueryPolicyAllowedParamsWithContext creates a new QueryPolicyAllowedParams object
// with the ability to set a context for a request.
func NewQueryPolicyAllowedParamsWithContext(ctx context.Context) *QueryPolicyAllowedParams {
	return &QueryPolicyAllowedParams{
		Context: ctx,
	}
}

// NewQueryPolicyAllowedParamsWithHTTPClient creates a new QueryPolicyAllowedParams object
// with the ability to set a custom HTTPClient for a request.
func NewQueryPolicyAllowedParamsWithHTTPClient(client *http.Client) *QueryPolicyAllowedParams {
	return &QueryPolicyAllowedParams{
		HTTPClient: client,
	}
}

/*
QueryPolicyAllowedParams contains all the parameters to send to the API endpoint

	for the query policy allowed operation.

	Typically these are written to a http.Request.
*/
type QueryPolicyAllowedParams struct {

	// Body.
	Body *models.Request

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the query policy allowed params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryPolicyAllowedParams) WithDefaults() *QueryPolicyAllowedParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the query policy allowed params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryPolicyAllowedParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the query policy allowed params
func (o *QueryPolicyAllowedParams) WithTimeout(timeout time.Duration) *QueryPolicyAllowedParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the query policy allowed params
func (o *QueryPolicyAllowedParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the query policy allowed params
func (o *QueryPolicyAllowedParams) WithContext(ctx context.Context) *QueryPolicyAllowedParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the query policy allowed params
func (o *QueryPolicyAllowedParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the query policy allowed params
func (o *QueryPolicyAllowedParams) WithHTTPClient(client *http.Client) *QueryPolicyAllowedParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the query policy allowed params
func (o *QueryPolicyAllowedParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the query policy allowed params
func (o *QueryPolicyAllowedParams) WithBody(body *models.Request) *QueryPolicyAllowedParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the query policy allowed params
func (o *QueryPolicyAllowedParams) SetBody(body *models.Request) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *QueryPolicyAllowedParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
