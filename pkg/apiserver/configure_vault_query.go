// Copyright 2023 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// This file is safe to edit. Once it exists it will not be overwritten

package apiserver

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"time"
	"vaultquery/pkg/common"
	policy_cache "vaultquery/pkg/data-cache"
	vault_helper "vaultquery/pkg/vault-helper"

	oerrors "github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	"github.com/hashicorp/vault/helper/namespace"
	gocache "github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"

	"vaultquery/pkg/apiserver/operations"
	astub "vaultquery/pkg/apiserver/operations/auth"
	gstub "vaultquery/pkg/apiserver/operations/group"
	pstub "vaultquery/pkg/apiserver/operations/policy"
)

//go:generate swagger generate server --target ../../../vault-query --name VaultQuery --spec ../../swagger.yaml --server-package pkg/apiserver --principal interface{} --exclude-main

var version string

var serverFlags = struct {
	NsAutoDiscover    bool `long:"ns-auto-discover" description:"Whether to auto discover namespaces"`
	NoAuth            bool `long:"no-auth" description:"Whether to require authentication for requests"`
	AutoDiscoverDepth int  `long:"ns-auto-discover-depth" description:"Depth at which to discover child namespaces - 0: top level ns, 1: child namespaces"`
	RefreshInterval   int  `long:"refresh-interval-seconds" description:"How often to refresh cache in seconds"`
}{}

func configureFlags(api *operations.VaultQueryAPI) {
	api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{
		{ShortDescription: "Server options", LongDescription: "", Options: &serverFlags},
	}
}

func configureAPI(api *operations.VaultQueryAPI) http.Handler {
	// configure the api here
	api.ServeError = oerrors.ServeError

	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	api.Logger = logrus.Printf
	logrus.SetLevel(logrus.DebugLevel)

	api.UseSwaggerUI()
	// To continue using redoc as your UI, uncomment the following line
	// api.UseRedoc()

	api.JSONConsumer = runtime.JSONConsumer()
	api.JSONProducer = runtime.JSONProducer()

	logrus.Info("Server Version: " + version)

	// Get the vault envs
	envVaultAddr, envVaultNs, envVaultToken := common.CollectVaultEnvs()
	if envVaultAddr == "" {
		logrus.Fatal("no vault addr in env vars")
	}
	if envVaultToken == "" {
		logrus.Fatal("no vault token in env vars")
	}
	if envVaultNs == "" {
		logrus.Warn("no namespace is provided")
	}
	envVaultNs = vault_helper.SanitiseNamespacePath(envVaultNs)

	logrus.Debugf("vault-addr: %s, vault-ns: %s", envVaultAddr, envVaultNs)
	vh, err := vault_helper.NewVaultHelper(envVaultAddr, envVaultNs, envVaultToken)
	if err != nil {
		logrus.Fatal(err, "\nerror creating vault helper client")
	}

	// Get all the namespace details
	var nsMap map[string]namespace.Namespace
	if serverFlags.NsAutoDiscover {
		nsMap, err = vh.ListNamespaceRecursive(serverFlags.AutoDiscoverDepth)
		if err != nil {
			logrus.Fatal(err, "\nerror listing namespaces")
		}
	} else {
		nsMap = map[string]namespace.Namespace{}
	}
	nsMap["root"] = namespace.Namespace{ // Fill out the root ns - there is no api to get the current namespace details
		ID:             "root",
		Path:           envVaultNs,
		CustomMetadata: nil,
	}
	nsPathToIdMap := map[string]string{} // create a map for easy conversion
	for _, nsInfo := range nsMap {
		nsPathToIdMap[nsInfo.Path] = nsInfo.ID
	}

	// Define metadata store
	metadataStore := gocache.New(gocache.NoExpiration, gocache.NoExpiration)
	for _, nsInfo := range nsMap {
		metadataStore.Set(nsInfo.Path+common.CacheReadyKey, false, gocache.NoExpiration)
	}

	// Define the policy cache service
	pc := policy_cache.VaultCache{
		RefreshInterval: time.Duration(serverFlags.RefreshInterval) * time.Second,
		VaultAddress:    envVaultAddr,
		VaultToken:      envVaultToken,
	}

	logrus.Debugln(nsMap)

	// Start the policy cache routing
	go func() {
		err := pc.Start(context.Background(), nsMap, metadataStore)
		if err != nil {
			logrus.Fatal(err, "\nerror running policy store") // if data-cache errors, its bad
		}
	}()

	// Applies when the "X-VAULT-TOKEN" header is set
	api.TokenAccessorAuthAuth = func(token string) (interface{}, error) {
		if !serverFlags.NoAuth {
			_, err := vh.TokenLookup(token)
			if err != nil {
				if strings.Contains(err.Error(), "bad token") {
					return false, nil
				} else {
					logrus.Error("unable to authenticate: " + err.Error())
					return false, errors.New("cannot authenticate")
				}
			} else {
				return true, nil
			}

		} else {
			logrus.Debug("authn: no auth enabled on server")
		}
		return "root", nil
	}

	// Handles /policy/fetch/{policyName}
	api.PolicyGetPolicyByNameHandler = pstub.GetPolicyByNameHandlerFunc(func(params pstub.GetPolicyByNameParams, principal interface{}) middleware.Responder {
		r := NewRequestHandler(pc.PolicyStore, pc.GroupStore, vh)
		if !principal.(bool) {
			return pstub.NewGetPolicyByNameUnauthorized().WithPayload(&pstub.GetPolicyByNameUnauthorizedBody{
				ID: r.requestId,
			})
		}
		return r.FetchPolicy(params, nsPathToIdMap)
	})

	// Handles /policy/query/allowed
	api.PolicyQueryPolicyAllowedHandler = pstub.QueryPolicyAllowedHandlerFunc(func(params pstub.QueryPolicyAllowedParams, principal interface{}) middleware.Responder {
		r := NewRequestHandler(pc.PolicyStore, pc.GroupStore, vh)
		if !principal.(bool) {
			return pstub.NewQueryPolicyAllowedUnauthorized().WithPayload(&pstub.QueryPolicyAllowedUnauthorizedBody{
				ID: r.requestId,
			})
		}
		return r.PolicyAllowed(params, nsPathToIdMap, nsMap)
	})

	// Handles /policy/search
	api.PolicySearchPolicyHandler = pstub.SearchPolicyHandlerFunc(func(params pstub.SearchPolicyParams, principal interface{}) middleware.Responder {
		r := NewRequestHandler(pc.PolicyStore, pc.GroupStore, vh)
		if !principal.(bool) {
			return pstub.NewSearchPolicyUnauthorized().WithPayload(&pstub.SearchPolicyUnauthorizedBody{
				ID: r.requestId,
			})
		}
		return r.SearchPolicy(params, nsPathToIdMap, nsMap)
	})

	// Handles /policy/tree
	api.PolicyPolicyTreeHandler = pstub.PolicyTreeHandlerFunc(func(params pstub.PolicyTreeParams, principal interface{}) middleware.Responder {
		r := NewRequestHandler(pc.PolicyStore, pc.GroupStore, vh)
		if !principal.(bool) {
			return pstub.NewPolicyTreeUnauthorized().WithPayload(&pstub.PolicyTreeUnauthorizedBody{
				ID: r.requestId,
			})
		}
		return r.PolicyTree(params, nsPathToIdMap, nsMap)
	})

	// Handles /groups/search/policy
	api.GroupSearchGroupWithPolicyHandler = gstub.SearchGroupWithPolicyHandlerFunc(func(params gstub.SearchGroupWithPolicyParams, principal interface{}) middleware.Responder {
		r := NewRequestHandler(pc.PolicyStore, pc.GroupStore, vh)
		if !principal.(bool) {
			return gstub.NewGetGroupByNameUnauthorized().WithPayload(&gstub.GetGroupByNameUnauthorizedBody{
				ID: r.requestId,
			})
		}
		return r.SearchGroupWithPolicy(params, nsPathToIdMap)
	})

	// Handles /auth/search/policy
	api.AuthSearchAuthWithPolicyHandler = astub.SearchAuthWithPolicyHandlerFunc(func(params astub.SearchAuthWithPolicyParams, principal interface{}) middleware.Responder {
		r := NewRequestHandler(pc.PolicyStore, pc.GroupStore, vh)
		if !principal.(bool) {
			return astub.NewSearchAuthWithPolicyUnauthorized().WithPayload(&astub.SearchAuthWithPolicyUnauthorizedBody{
				ID: r.requestId,
			})
		}
		return r.SearchAuthRoleWithPolicy(params, nsPathToIdMap)
	})

	api.PreServerShutdown = func() {}

	api.ServerShutdown = func() {}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix".
func configureServer(s *http.Server, scheme, addr string) {
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation.
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics.
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	return handler
}
