// Code generated by go-swagger; DO NOT EDIT.

package auth

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

// NewSearchAuthWithPolicyParams creates a new SearchAuthWithPolicyParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewSearchAuthWithPolicyParams() *SearchAuthWithPolicyParams {
	return &SearchAuthWithPolicyParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewSearchAuthWithPolicyParamsWithTimeout creates a new SearchAuthWithPolicyParams object
// with the ability to set a timeout on a request.
func NewSearchAuthWithPolicyParamsWithTimeout(timeout time.Duration) *SearchAuthWithPolicyParams {
	return &SearchAuthWithPolicyParams{
		timeout: timeout,
	}
}

// NewSearchAuthWithPolicyParamsWithContext creates a new SearchAuthWithPolicyParams object
// with the ability to set a context for a request.
func NewSearchAuthWithPolicyParamsWithContext(ctx context.Context) *SearchAuthWithPolicyParams {
	return &SearchAuthWithPolicyParams{
		Context: ctx,
	}
}

// NewSearchAuthWithPolicyParamsWithHTTPClient creates a new SearchAuthWithPolicyParams object
// with the ability to set a custom HTTPClient for a request.
func NewSearchAuthWithPolicyParamsWithHTTPClient(client *http.Client) *SearchAuthWithPolicyParams {
	return &SearchAuthWithPolicyParams{
		HTTPClient: client,
	}
}

/*
SearchAuthWithPolicyParams contains all the parameters to send to the API endpoint

	for the search auth with policy operation.

	Typically these are written to a http.Request.
*/
type SearchAuthWithPolicyParams struct {

	/* Namespace.

	   Namespace of the policy
	*/
	Namespace string

	/* PolicyName.

	   Name of policy
	*/
	PolicyName string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the search auth with policy params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SearchAuthWithPolicyParams) WithDefaults() *SearchAuthWithPolicyParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the search auth with policy params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SearchAuthWithPolicyParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the search auth with policy params
func (o *SearchAuthWithPolicyParams) WithTimeout(timeout time.Duration) *SearchAuthWithPolicyParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the search auth with policy params
func (o *SearchAuthWithPolicyParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the search auth with policy params
func (o *SearchAuthWithPolicyParams) WithContext(ctx context.Context) *SearchAuthWithPolicyParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the search auth with policy params
func (o *SearchAuthWithPolicyParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the search auth with policy params
func (o *SearchAuthWithPolicyParams) WithHTTPClient(client *http.Client) *SearchAuthWithPolicyParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the search auth with policy params
func (o *SearchAuthWithPolicyParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithNamespace adds the namespace to the search auth with policy params
func (o *SearchAuthWithPolicyParams) WithNamespace(namespace string) *SearchAuthWithPolicyParams {
	o.SetNamespace(namespace)
	return o
}

// SetNamespace adds the namespace to the search auth with policy params
func (o *SearchAuthWithPolicyParams) SetNamespace(namespace string) {
	o.Namespace = namespace
}

// WithPolicyName adds the policyName to the search auth with policy params
func (o *SearchAuthWithPolicyParams) WithPolicyName(policyName string) *SearchAuthWithPolicyParams {
	o.SetPolicyName(policyName)
	return o
}

// SetPolicyName adds the policyName to the search auth with policy params
func (o *SearchAuthWithPolicyParams) SetPolicyName(policyName string) {
	o.PolicyName = policyName
}

// WriteToRequest writes these params to a swagger request
func (o *SearchAuthWithPolicyParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param namespace
	qrNamespace := o.Namespace
	qNamespace := qrNamespace
	if qNamespace != "" {

		if err := r.SetQueryParam("namespace", qNamespace); err != nil {
			return err
		}
	}

	// query param policyName
	qrPolicyName := o.PolicyName
	qPolicyName := qrPolicyName
	if qPolicyName != "" {

		if err := r.SetQueryParam("policyName", qPolicyName); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
