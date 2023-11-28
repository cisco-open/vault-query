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
)

// NewGetPolicyByNameParams creates a new GetPolicyByNameParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetPolicyByNameParams() *GetPolicyByNameParams {
	return &GetPolicyByNameParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetPolicyByNameParamsWithTimeout creates a new GetPolicyByNameParams object
// with the ability to set a timeout on a request.
func NewGetPolicyByNameParamsWithTimeout(timeout time.Duration) *GetPolicyByNameParams {
	return &GetPolicyByNameParams{
		timeout: timeout,
	}
}

// NewGetPolicyByNameParamsWithContext creates a new GetPolicyByNameParams object
// with the ability to set a context for a request.
func NewGetPolicyByNameParamsWithContext(ctx context.Context) *GetPolicyByNameParams {
	return &GetPolicyByNameParams{
		Context: ctx,
	}
}

// NewGetPolicyByNameParamsWithHTTPClient creates a new GetPolicyByNameParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetPolicyByNameParamsWithHTTPClient(client *http.Client) *GetPolicyByNameParams {
	return &GetPolicyByNameParams{
		HTTPClient: client,
	}
}

/*
GetPolicyByNameParams contains all the parameters to send to the API endpoint

	for the get policy by name operation.

	Typically these are written to a http.Request.
*/
type GetPolicyByNameParams struct {

	/* Namespace.

	   namespace of the policy
	*/
	Namespace *string

	/* PolicyName.

	   name of the policy
	*/
	PolicyName string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get policy by name params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetPolicyByNameParams) WithDefaults() *GetPolicyByNameParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get policy by name params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetPolicyByNameParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get policy by name params
func (o *GetPolicyByNameParams) WithTimeout(timeout time.Duration) *GetPolicyByNameParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get policy by name params
func (o *GetPolicyByNameParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get policy by name params
func (o *GetPolicyByNameParams) WithContext(ctx context.Context) *GetPolicyByNameParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get policy by name params
func (o *GetPolicyByNameParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get policy by name params
func (o *GetPolicyByNameParams) WithHTTPClient(client *http.Client) *GetPolicyByNameParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get policy by name params
func (o *GetPolicyByNameParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithNamespace adds the namespace to the get policy by name params
func (o *GetPolicyByNameParams) WithNamespace(namespace *string) *GetPolicyByNameParams {
	o.SetNamespace(namespace)
	return o
}

// SetNamespace adds the namespace to the get policy by name params
func (o *GetPolicyByNameParams) SetNamespace(namespace *string) {
	o.Namespace = namespace
}

// WithPolicyName adds the policyName to the get policy by name params
func (o *GetPolicyByNameParams) WithPolicyName(policyName string) *GetPolicyByNameParams {
	o.SetPolicyName(policyName)
	return o
}

// SetPolicyName adds the policyName to the get policy by name params
func (o *GetPolicyByNameParams) SetPolicyName(policyName string) {
	o.PolicyName = policyName
}

// WriteToRequest writes these params to a swagger request
func (o *GetPolicyByNameParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Namespace != nil {

		// query param namespace
		var qrNamespace string

		if o.Namespace != nil {
			qrNamespace = *o.Namespace
		}
		qNamespace := qrNamespace
		if qNamespace != "" {

			if err := r.SetQueryParam("namespace", qNamespace); err != nil {
				return err
			}
		}
	}

	// path param policyName
	if err := r.SetPathParam("policyName", o.PolicyName); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}