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

// NewPolicyTreeParams creates a new PolicyTreeParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPolicyTreeParams() *PolicyTreeParams {
	return &PolicyTreeParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPolicyTreeParamsWithTimeout creates a new PolicyTreeParams object
// with the ability to set a timeout on a request.
func NewPolicyTreeParamsWithTimeout(timeout time.Duration) *PolicyTreeParams {
	return &PolicyTreeParams{
		timeout: timeout,
	}
}

// NewPolicyTreeParamsWithContext creates a new PolicyTreeParams object
// with the ability to set a context for a request.
func NewPolicyTreeParamsWithContext(ctx context.Context) *PolicyTreeParams {
	return &PolicyTreeParams{
		Context: ctx,
	}
}

// NewPolicyTreeParamsWithHTTPClient creates a new PolicyTreeParams object
// with the ability to set a custom HTTPClient for a request.
func NewPolicyTreeParamsWithHTTPClient(client *http.Client) *PolicyTreeParams {
	return &PolicyTreeParams{
		HTTPClient: client,
	}
}

/*
PolicyTreeParams contains all the parameters to send to the API endpoint

	for the policy tree operation.

	Typically these are written to a http.Request.
*/
type PolicyTreeParams struct {

	// Body.
	Body *models.Request

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the policy tree params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PolicyTreeParams) WithDefaults() *PolicyTreeParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the policy tree params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PolicyTreeParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the policy tree params
func (o *PolicyTreeParams) WithTimeout(timeout time.Duration) *PolicyTreeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the policy tree params
func (o *PolicyTreeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the policy tree params
func (o *PolicyTreeParams) WithContext(ctx context.Context) *PolicyTreeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the policy tree params
func (o *PolicyTreeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the policy tree params
func (o *PolicyTreeParams) WithHTTPClient(client *http.Client) *PolicyTreeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the policy tree params
func (o *PolicyTreeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the policy tree params
func (o *PolicyTreeParams) WithBody(body *models.Request) *PolicyTreeParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the policy tree params
func (o *PolicyTreeParams) SetBody(body *models.Request) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PolicyTreeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
