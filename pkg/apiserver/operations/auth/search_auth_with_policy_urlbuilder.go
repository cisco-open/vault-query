// Code generated by go-swagger; DO NOT EDIT.

package auth

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"errors"
	"net/url"
	golangswaggerpaths "path"
)

// SearchAuthWithPolicyURL generates an URL for the search auth with policy operation
type SearchAuthWithPolicyURL struct {
	Namespace  string
	PolicyName string

	_basePath string
	// avoid unkeyed usage
	_ struct{}
}

// WithBasePath sets the base path for this url builder, only required when it's different from the
// base path specified in the swagger spec.
// When the value of the base path is an empty string
func (o *SearchAuthWithPolicyURL) WithBasePath(bp string) *SearchAuthWithPolicyURL {
	o.SetBasePath(bp)
	return o
}

// SetBasePath sets the base path for this url builder, only required when it's different from the
// base path specified in the swagger spec.
// When the value of the base path is an empty string
func (o *SearchAuthWithPolicyURL) SetBasePath(bp string) {
	o._basePath = bp
}

// Build a url path and query string
func (o *SearchAuthWithPolicyURL) Build() (*url.URL, error) {
	var _result url.URL

	var _path = "/auth/search/policy"

	_basePath := o._basePath
	_result.Path = golangswaggerpaths.Join(_basePath, _path)

	qs := make(url.Values)

	namespaceQ := o.Namespace
	if namespaceQ != "" {
		qs.Set("namespace", namespaceQ)
	}

	policyNameQ := o.PolicyName
	if policyNameQ != "" {
		qs.Set("policyName", policyNameQ)
	}

	_result.RawQuery = qs.Encode()

	return &_result, nil
}

// Must is a helper function to panic when the url builder returns an error
func (o *SearchAuthWithPolicyURL) Must(u *url.URL, err error) *url.URL {
	if err != nil {
		panic(err)
	}
	if u == nil {
		panic("url can't be nil")
	}
	return u
}

// String returns the string representation of the path with query string
func (o *SearchAuthWithPolicyURL) String() string {
	return o.Must(o.Build()).String()
}

// BuildFull builds a full url with scheme, host, path and query string
func (o *SearchAuthWithPolicyURL) BuildFull(scheme, host string) (*url.URL, error) {
	if scheme == "" {
		return nil, errors.New("scheme is required for a full url on SearchAuthWithPolicyURL")
	}
	if host == "" {
		return nil, errors.New("host is required for a full url on SearchAuthWithPolicyURL")
	}

	base, err := o.Build()
	if err != nil {
		return nil, err
	}

	base.Scheme = scheme
	base.Host = host
	return base, nil
}

// StringFull returns the string representation of a complete url
func (o *SearchAuthWithPolicyURL) StringFull(scheme, host string) string {
	return o.Must(o.BuildFull(scheme, host)).String()
}
