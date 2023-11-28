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

// This file is safe to edit.

package apiserver

import (
	"context"
	"fmt"
	"github.com/go-openapi/runtime/middleware"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/helper/namespace"
	_ "github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
	gocache "github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"vaultquery/models"
	astub "vaultquery/pkg/apiserver/operations/auth"
	gstub "vaultquery/pkg/apiserver/operations/group"
	pstub "vaultquery/pkg/apiserver/operations/policy"
	data_cache "vaultquery/pkg/data-cache"
	"vaultquery/pkg/trie"
	vault_helper "vaultquery/pkg/vault-helper"
)

type RequestHandler struct {
	requestId   string
	logger      *logrus.Entry
	policyCache map[string]*gocache.Cache
	groupCache  map[string]*gocache.Cache
	vh          vault_helper.VaultHelper
}

func NewRequestHandler(policyCache map[string]*gocache.Cache, groupCache map[string]*gocache.Cache, vh vault_helper.VaultHelper) RequestHandler {
	reqId, _ := uuid.NewUUID()
	loggr := logrus.WithFields(logrus.Fields{"reqId": reqId.String()})
	return RequestHandler{
		requestId:   reqId.String(),
		logger:      loggr,
		policyCache: policyCache,
		groupCache:  groupCache,
		vh:          vh,
	}
}

func (r *RequestHandler) FetchPolicy(params pstub.GetPolicyByNameParams, nsPathToIdMap map[string]string) middleware.Responder {
	// Get the namespace Id from path
	nsPath := vault_helper.SanitiseNamespacePath(*params.Namespace)
	nsId, ok := nsPathToIdMap[nsPath]
	if !ok {
		return pstub.NewGetPolicyByNameBadRequest().WithPayload(&pstub.GetPolicyByNameBadRequestBody{ID: r.requestId,
			Messages: []*models.Message{
				{
					MsgBody: "namespace not supported " + nsPath,
					MsgType: models.MessageMsgTypeErr,
				},
			}})
	}

	// Get the policy
	p, found, err := r.getRawPolicy(params.PolicyName, nsId)
	if err != nil {
		return pstub.NewGetPolicyByNameInternalServerError().WithPayload(&pstub.GetPolicyByNameInternalServerErrorBody{ID: r.requestId})
	}
	if !found {
		return pstub.NewGetPolicyByNameNotFound().WithPayload(&pstub.GetPolicyByNameNotFoundBody{ID: r.requestId})
	}

	// Return the policy
	return pstub.NewGetPolicyByNameOK().WithPayload(&pstub.GetPolicyByNameOKBody{
		PolicyName: params.PolicyName,
		PolicyRaw:  p,
	})
}

func (r *RequestHandler) PolicyAllowed(params pstub.QueryPolicyAllowedParams, nsPathToIdMap map[string]string, nsMap map[string]namespace.Namespace) middleware.Responder {
	messages := []*models.Message{}

	// Get the policy names form the request
	policyNames, msgs := r.getPolicyNamesFromRequest(params.Body, nsPathToIdMap)
	messages = append(messages, msgs...)
	r.logger.Debug(policyNames)

	customRawPolicy := params.Body.RawPolicy != nil && *params.Body.RawPolicy.Policy != ""
	if len(policyNames) == 0 && !customRawPolicy {
		r.logger.Error("no policies to evaluate")
		msgs = append(msgs, &models.Message{
			MsgBody: "no policies to evaluate",
			MsgType: models.MessageMsgTypeErr,
		})
		return pstub.NewQueryPolicyAllowedBadRequest().WithPayload(&pstub.QueryPolicyAllowedBadRequestBody{ID: r.requestId,
			Messages: msgs})
	}

	//Get the namespace id for the request
	requestNsPath := vault_helper.SanitiseNamespacePath(params.Body.PathDetails.Namespace)
	requestNsId, ok := nsPathToIdMap[requestNsPath]
	if !ok {
		r.logger.Error("could not find ns id for path: " + requestNsPath)
		messages = append(messages, &models.Message{
			MsgBody: "could not find namespace (in request): " + requestNsPath,
			MsgType: models.MessageMsgTypeErr,
		})
		return pstub.NewQueryPolicyAllowedBadRequest().WithPayload(&pstub.QueryPolicyAllowedBadRequestBody{ID: r.requestId,
			Messages: messages})
	}
	requestNs := nsMap[requestNsId]

	// Get all the policies
	reqPolicySegments, reqDenyPolicySegments, msgs := r.getPolicySegments(policyNames, nsMap)
	messages = append(messages, msgs...)

	// Get policy Segments from custom raw policy (if any)
	msgs, err := r.checkAndParseRawPolicy(params.Body, nsPathToIdMap, nsMap, &reqPolicySegments, &reqDenyPolicySegments)
	messages = append(messages, msgs...)
	if err != nil {
		messages = append(messages,
			&models.Message{
				MsgBody: "error parsing custom policy",
				MsgType: models.MessageMsgTypeErr,
			})
		return pstub.NewQueryPolicyAllowedBadRequest().WithPayload(&pstub.QueryPolicyAllowedBadRequestBody{ID: r.requestId,
			Messages: messages})
	}

	// Create a list of policySegments
	policySegmentList := []*vault.Policy{}
	for _, ps := range reqPolicySegments {
		policySegmentList = append(policySegmentList, ps)
	}
	denyPolicySegmentList := []*vault.Policy{}
	for _, ps := range reqDenyPolicySegments {
		denyPolicySegmentList = append(denyPolicySegmentList, ps)
	}

	// Build ACL from policies
	acl, err := r.buildAcl(params.HTTPRequest.Context(), requestNs, policySegmentList)
	if err != nil {
		r.logger.Error(errors.Wrap(err, "error building token acl"))
		return pstub.NewQueryPolicyAllowedInternalServerError()
	}

	// Build deny ACL from policies (policy segments with deny in them)
	denyAcl, err := r.buildAcl(params.HTTPRequest.Context(), requestNs, denyPolicySegmentList)
	if err != nil {
		r.logger.Error(errors.Wrap(err, "error building deny token acl"))
		return pstub.NewQueryPolicyAllowedInternalServerError()
	}

	vCtx := namespace.ContextWithNamespace(params.HTTPRequest.Context(), &requestNs)

	requestPath := params.Body.PathDetails.Path
	requestOp := logical.Operation(params.Body.PathDetails.Op)

	// Check if the operation is allowed
	aclRes := acl.AllowOperation(vCtx, &logical.Request{
		Path:      requestPath,
		Operation: requestOp,
	}, false)

	// Get the allowed capabilities for the path
	resCap := acl.Capabilities(vCtx, requestPath)

	r.logger.Debugf("path %s for op %s is allowed? %v", requestNs.Path+requestPath,
		params.Body.PathDetails.Op, aclRes.Allowed)

	resp := models.Response{
		AllowedCap:             []string{},
		DenyingPolicySegments:  map[string]map[string][]models.PolicySegment{},
		GrantingPolicySegments: map[string]map[string][]models.PolicySegment{},
		Messages:               messages,
	}

	resp.Allowed = &aclRes.Allowed

	if aclRes.Allowed {
		// Get the granting policies, find the right segment and add it to the response
		for _, gp := range aclRes.GrantingPolicies {
			policyName := data_cache.GetPolicyNameFromSegmentName(gp.Name)
			policy := reqPolicySegments[gp.Name]
			policyNsPath := nsMap[gp.NamespaceId].Path
			if _, ok := resp.GrantingPolicySegments[policyNsPath]; !ok {
				resp.GrantingPolicySegments[policyNsPath] = map[string][]models.PolicySegment{}
			}
			resp.GrantingPolicySegments[policyNsPath][policyName] = append(resp.GrantingPolicySegments[gp.NamespaceId][policyName],
				models.PolicySegment{
					Raw:  policy.Raw,
					Name: gp.Name,
				})
		}
		resp.AllowedCap = resCap
	} else {
		// Operation not allowed :(
		// Check for a denying policy
		dRes := denyAcl.AllowOperation(vCtx, &logical.Request{
			Path:      requestPath,
			Operation: logical.ReadOperation, // We use read operation as this is what "deny" is replaced with in the original policy
		}, false)
		if dRes.Allowed { // Denying policy found!
			// Get the denying policies, find the right segment and add it to the response
			for _, gp := range dRes.GrantingPolicies {
				policyName := data_cache.GetPolicyNameFromSegmentName(gp.Name)
				denyingPolicy := reqDenyPolicySegments[gp.Name]
				policyNsPath := nsMap[gp.NamespaceId].Path
				if _, ok := resp.DenyingPolicySegments[policyNsPath]; !ok {
					resp.DenyingPolicySegments[policyNsPath] = map[string][]models.PolicySegment{}
				}
				resp.DenyingPolicySegments[policyNsPath][policyName] = append(resp.DenyingPolicySegments[gp.NamespaceId][policyName],
					models.PolicySegment{
						Raw:  denyingPolicy.Raw,
						Name: gp.Name,
					})
			}
		}
	}

	return pstub.NewQueryPolicyAllowedOK().WithPayload(&resp)
}

func (r *RequestHandler) SearchPolicy(params pstub.SearchPolicyParams, nsPathToIdMap map[string]string,
	nsMap map[string]namespace.Namespace) middleware.Responder {
	//Get the namespace id for the request
	requestNsPath := vault_helper.SanitiseNamespacePath(params.Body.PathDetails.Namespace)
	requestNsId, ok := nsPathToIdMap[requestNsPath]
	if !ok {
		r.logger.Error("could not find ns id for path: " + requestNsPath)
		return pstub.NewSearchPolicyBadRequest().WithPayload(&pstub.SearchPolicyBadRequestBody{ID: r.requestId,
			Messages: []*models.Message{
				{
					MsgBody: "namespace (in request) not supported " + requestNsPath,
					MsgType: models.MessageMsgTypeErr,
				},
			}})
	}
	requestNs := nsMap[requestNsId]

	allowingPolicies, denyingPolicies := r.searchPolicy(params.HTTPRequest.Context(), params.Body.PathDetails.Path, params.Body.PathDetails.Op, requestNs, nsMap)

	return pstub.NewSearchPolicyOK().WithPayload(&pstub.SearchPolicyOKBody{
		GrantingPolicySegments: allowingPolicies,
		DenyingPolicySegments:  denyingPolicies})
}

func (r *RequestHandler) PolicyTree(params pstub.PolicyTreeParams, nsPathToIdMap map[string]string,
	nsMap map[string]namespace.Namespace) middleware.Responder {
	messages := []*models.Message{}

	// Get the policy names form the request
	policyNames, msgs := r.getPolicyNamesFromRequest(params.Body, nsPathToIdMap)
	messages = append(messages, msgs...)
	r.logger.Debug(policyNames)

	customRawPolicy := params.Body.RawPolicy != nil && *params.Body.RawPolicy.Policy != ""
	if len(policyNames) == 0 && !customRawPolicy {
		r.logger.Error("no policies to evaluate")
		msgs = append(msgs, &models.Message{
			MsgBody: "no policies to evaluate",
			MsgType: models.MessageMsgTypeErr,
		})
		return pstub.NewQueryPolicyAllowedBadRequest().WithPayload(&pstub.QueryPolicyAllowedBadRequestBody{ID: r.requestId,
			Messages: msgs})
	}

	reqPolicySegments, reqDenyPolicySegments, msgs := r.getPolicySegments(policyNames, nsMap)
	messages = append(messages, msgs...)

	// Get policy Segments from custom raw policy (if any)
	msgs, err := r.checkAndParseRawPolicy(params.Body, nsPathToIdMap, nsMap, &reqPolicySegments, &reqDenyPolicySegments)
	messages = append(messages, msgs...)
	if err != nil {
		messages = append(messages,
			&models.Message{
				MsgBody: "error parsing custom policy",
				MsgType: models.MessageMsgTypeErr,
			})
		return pstub.NewQueryPolicyAllowedBadRequest().WithPayload(&pstub.QueryPolicyAllowedBadRequestBody{ID: r.requestId,
			Messages: messages})
	}

	t := trie.NewTree()

	capUpdateFunc := func(old interface{}, new interface{}) interface{} {
		o, okO := old.([]string)
		n, okN := new.([]string)
		if !okO && !okN {
			return []string{}
		}
		if !okO && okN {
			return n
		}
		if okO && !okN {
			return o
		}
		set := map[string]bool{}
		for _, k := range o {
			set[k] = true
		}
		for _, k := range n {
			set[k] = true
		}
		setSlice := []string{}
		for k, _ := range set {
			setSlice = append(setSlice, k)
		}
		return setSlice
	}

	// Insert all the policy segments
	r.logger.Debug("building tree")
	for _, policy := range reqPolicySegments {
		for _, path := range policy.Paths {
			if path.IsPrefix {
				t.Insert(path.Path+"*", path.Capabilities, &capUpdateFunc)
			} else {
				t.Insert(path.Path, path.Capabilities, &capUpdateFunc)
			}

		}
	}

	// Insert all the "deny" policy segments
	for _, policy := range reqDenyPolicySegments {
		for _, path := range policy.Paths {
			if path.IsPrefix {
				t.Insert(path.Path+"*", []string{"deny"}, &capUpdateFunc)
			} else {
				t.Insert(path.Path, []string{"deny"}, &capUpdateFunc)
			}
		}
	}
	return pstub.NewPolicyTreeOK().WithPayload(&pstub.PolicyTreeOKBody{Tree: t, Messages: messages})
}

func (r *RequestHandler) SearchGroupWithPolicy(params gstub.SearchGroupWithPolicyParams, nsPathToIdMap map[string]string) middleware.Responder {
	//Get the namespace id for the request
	requestNsPath := vault_helper.SanitiseNamespacePath(params.Namespace)
	requestNsId, ok := nsPathToIdMap[requestNsPath]
	if !ok {
		r.logger.Error("could not find ns id for path: " + requestNsPath)
		return gstub.NewSearchGroupWithPolicyBadRequest().WithPayload(&gstub.SearchGroupWithPolicyBadRequestBody{
			ID: r.requestId,
			Messages: []*models.Message{
				{
					MsgBody: "namespace (in request) not supported " + requestNsPath,
					MsgType: models.MessageMsgTypeErr,
				},
			}})
	}
	// Get the groups from that policy
	r.logger.Debugf("getting groutps for policy %s [%s]", params.PolicyName, params.Namespace)
	groups, additionalGroups, policyFound, err := r.searchGroupWithPolicy(params.PolicyName, requestNsId)
	if err != nil {
		r.logger.Error(errors.Wrap(err, "error finding group with policy "+params.PolicyName))
		return gstub.NewSearchGroupWithPolicyInternalServerError().WithPayload(&gstub.SearchGroupWithPolicyInternalServerErrorBody{
			ID: r.requestId,
		})
	}
	if !policyFound {
		return gstub.NewSearchGroupWithPolicyNotFound().WithPayload(&gstub.SearchGroupWithPolicyNotFoundBody{
			ID: r.requestId,
		})
	}
	r.logger.Debugf("groups found: %v", groups)
	groupsMap := map[string]interface{}{}
	for gid, g := range groups {
		groupsMap[gid] = g
	}
	additionalGroupsMap := map[string]interface{}{}
	for _, g := range additionalGroups {
		additionalGroupsMap[g.ID] = g
	}
	return gstub.NewSearchGroupWithPolicyOK().WithPayload(&gstub.SearchGroupWithPolicyOKBody{
		Groups:           groupsMap,
		AdditionalGroups: additionalGroupsMap,
	})
}

func (r *RequestHandler) SearchAuthRoleWithPolicy(params astub.SearchAuthWithPolicyParams, nsPathToIdMap map[string]string) middleware.Responder {
	//Get the namespace id for the request
	requestNsPath := vault_helper.SanitiseNamespacePath(params.Namespace)
	requestNsId, ok := nsPathToIdMap[requestNsPath]
	if !ok {
		r.logger.Error("could not find ns id for path: " + requestNsPath)
		return astub.NewSearchAuthWithPolicyBadRequest().WithPayload(&astub.SearchAuthWithPolicyBadRequestBody{
			ID: r.requestId,
			Messages: []*models.Message{
				{
					MsgBody: "namespace (in request) not supported " + requestNsPath,
					MsgType: models.MessageMsgTypeErr,
				},
			}})
	}
	// Get the auth roles from that policy
	r.logger.Debugf("getting auth roles for policy %s [%s]", params.PolicyName, params.Namespace)
	authRoles, policyFound, err := r.searchAuthRolesWithPolicy(params.PolicyName, requestNsId)
	if err != nil {
		r.logger.Error(errors.Wrap(err, "error finding auth role with policy "+params.PolicyName))
		return astub.NewSearchAuthWithPolicyInternalServerError().WithPayload(&astub.SearchAuthWithPolicyInternalServerErrorBody{
			ID: r.requestId,
		})
	}
	if !policyFound {
		r.logger.Error("policy not found")
		return astub.NewSearchAuthWithPolicyNotFound().WithPayload(&astub.SearchAuthWithPolicyNotFoundBody{
			ID: r.requestId,
		})
	}
	r.logger.Debugf("auth roles found! %v", authRoles)
	responseBody := map[string][]interface{}{}
	for t, roles := range authRoles {
		for _, authRole := range roles {
			responseBody[t] = append(responseBody[t], authRole)
		}
	}
	return astub.NewSearchAuthWithPolicyOK().WithPayload(&astub.SearchAuthWithPolicyOKBody{AuthRoles: responseBody})
}

func (r *RequestHandler) getRawPolicy(policyName, namespaceId string) (string, bool, error) {
	r.logger.Debugf("Getting policy %s, %s", policyName, namespaceId)
	cpRaw, found := r.policyCache[namespaceId].Get(policyName)
	if !found {
		r.logger.Error("could not find policy in cache store")
		return "", false, nil
	}
	cachedPolicy, ok := cpRaw.(*data_cache.CachedPolicy)
	if !ok {
		r.logger.Error("could not cast to data_cache.CachedPolicy")
		return "", found, errors.New("could not cast to data_cache.CachedPolicy")
	}

	return cachedPolicy.Policy.Raw, found, nil
}

func (r *RequestHandler) getPolicyNamesFromRequest(req *models.Request, nsPathToIdMap map[string]string) (map[string][]string, []*models.Message) {
	policyNames := map[string][]string{}
	msgs := []*models.Message{}
	explicitPolicies := false
	tokenPolicies := false
	if req != nil && len(req.Policies) > 0 {
		explicitPolicies = true
	}
	if req != nil && req.TokenDetails != nil &&
		(len(req.TokenDetails.Policies) > 0 || len(req.TokenDetails.IdentityPolicies) > 0 || len(req.TokenDetails.ExternalNamespacePolicies) > 0) {
		tokenPolicies = true
	}

	if tokenPolicies { // Policy names supplied as part of token
		tokenDetails := req.TokenDetails

		// Get the namespace Id from path
		r.logger.Debug("getting namespace id from path")
		tokenNsPath := vault_helper.SanitiseNamespacePath(tokenDetails.NamespacePath)
		tokenNsId, ok := nsPathToIdMap[tokenNsPath]
		if ok {
			// Generate list of policies from the token details
			policyNames[tokenNsId] = []string{}
			policyNames[tokenNsId] = append(policyNames[tokenNsId], tokenDetails.Policies...)
			policyNames[tokenNsId] = append(policyNames[tokenNsId], tokenDetails.IdentityPolicies...)
			for nsId, ps := range tokenDetails.ExternalNamespacePolicies {
				policyNames[nsId] = append(policyNames[nsId], ps...)
			}
		} else {
			r.logger.Error("could not find ns id for path: " + tokenNsPath)
			msgs = append(msgs, &models.Message{
				MsgBody: "namespace not found " + tokenNsPath + ", ignoring...",
				MsgType: models.MessageMsgTypeWarn,
			})
		}
	}

	if explicitPolicies { // Policy names provided explicitly
		r.logger.Debug("getting policies from request, and mapping them to nsIds")
		for nsPath, policies := range req.Policies {
			nsPath = vault_helper.SanitiseNamespacePath(nsPath)
			nsId, ok := nsPathToIdMap[nsPath]
			if ok {
				for _, policyName := range policies {
					policyNames[nsId] = append(policyNames[nsId], policyName)
				}
			} else {
				r.logger.Error("could not find ns id for path: " + nsPath)
				msgs = append(msgs, &models.Message{
					MsgBody: "namespace not found " + nsPath + ", ignoring...",
					MsgType: models.MessageMsgTypeWarn,
				})
			}
		}
	}
	return policyNames, msgs
}

// getPolicySegments gets all the policy segments (as separate policy objects) from the cache
// it also returns deny policy segments (deny parts of a policies) as separate ,ap
// expects a map[namespaceId][policyNames]
// also expects a namespace map (map[namespaceId]Namespace) but only used for debugging
// return two lists of parsed policies, one for all segments, one for all deny segments
// For e.g. request for {"ns-a": ["policy-a"]}
// where policy-a is:
//
//	path "a/b/c" { capabilities = ["read", "write"] } // policy-a-1
//	path "d/e/f" { capabilities = ["read", "write"] } // policy-a-2
//	path "g/h/i" { capabilities = ["deny"] }          // policy-a-3 (segment with deny)
//
// will return the following:
// map[policy-a-1: .., policy-a-2: ...],  map[policy-a-3: ...]
func (r *RequestHandler) getPolicySegments(policyNamesPerNs map[string][]string, nsMap map[string]namespace.Namespace) (map[string]*vault.Policy, map[string]*vault.Policy, []*models.Message) {
	r.logger.Debug("getting policies from cache")
	msgs := []*models.Message{}
	policySegments := map[string]*vault.Policy{}
	denySegments := map[string]*vault.Policy{}
	for nsId, policyNames := range policyNamesPerNs {
		policyCache, ok := r.policyCache[nsId]
		ns, ok := nsMap[nsId]
		_nsPath := "" // WARNING: only use for debugging and logging
		if ok {
			_nsPath = ns.Path
		} else {
			_nsPath = "<unknown>"
		}
		if !ok {
			errorMsg := fmt.Sprintf("namespace not found with path %s (%s)", _nsPath, nsId)
			msgs = append(msgs, &models.Message{
				MsgBody: errorMsg,
				MsgType: models.MessageMsgTypeWarn,
			})
			r.logger.Error(errorMsg)
			continue
		}
		for _, policyName := range policyNames {
			cp, found := policyCache.Get(policyName)
			if !found {
				errMsg := fmt.Sprintf("policy not found %s in namespace %s (%s), ignoring...", policyName, _nsPath, nsId)
				r.logger.Warn(errMsg)
				msgs = append(msgs, &models.Message{
					MsgBody: errMsg,
					MsgType: models.MessageMsgTypeWarn,
				})
				continue
			}
			cachedPolicy, ok := cp.(*data_cache.CachedPolicy)
			if !ok {
				r.logger.Errorf("policy with name: %s in %s (%s) cannot be type casted, %v", policyName, _nsPath, nsId, cp)
				msgs = append(msgs, &models.Message{
					MsgBody: fmt.Sprintf("policy could not be evaluated, name: %s, namespace: %s (%s), ignoring...", policyName, _nsPath, nsId),
					MsgType: models.MessageMsgTypeWarn,
				})
				continue
			}
			// Add all pathSegments to policySegments map
			for name, ps := range cachedPolicy.PathSegments {
				policySegments[name] = ps
			}
			// Add all "deny" pathSegments to denySegments map
			for name, ps := range cachedPolicy.DenyPathSegment {
				denySegments[name] = ps
			}
		}
	}
	return policySegments, denySegments, msgs
}

// checkAndParseRawPolicy checks whether there is a raw policy in the request, and parses the policy
// takes two maps for pathSegments and denySegments, and populates them with parsed policy segments
// returns error - which is safe to pass back to user
func (r *RequestHandler) checkAndParseRawPolicy(request *models.Request, nsPathToIdMap map[string]string,
	nsMap map[string]namespace.Namespace, pathSegments *map[string]*vault.Policy, denySegments *map[string]*vault.Policy) ([]*models.Message, error) {

	msgs := []*models.Message{}

	customRawPolicy := request.RawPolicy != nil && request.RawPolicy.Policy != nil && *request.RawPolicy.Policy != ""
	//Parse any custom policy and add it to the policy array
	if customRawPolicy {
		nsId, ok := nsPathToIdMap[vault_helper.SanitiseNamespacePath(*request.RawPolicy.Namespace)]
		if !ok {
			msgs = append(msgs, &models.Message{
				MsgBody: "namespace (for custom policy) not supported, ns path: " + *request.RawPolicy.Namespace,
				MsgType: models.MessageMsgTypeErr,
			})
			return msgs, errors.New("custom policy: could not find ns id for ns path: " + *request.RawPolicy.Namespace)
		}
		policyNs := nsMap[nsId]
		cp, err := data_cache.ParsePolicy(context.Background(), *request.RawPolicy.Name, *request.RawPolicy.Policy, policyNs)
		if err != nil {
			msgs = append(msgs, &models.Message{
				MsgBody: "error parsing raw policy",
				MsgType: models.MessageMsgTypeErr,
			})
			return msgs, errors.Wrap(err, "error parsing raw policy")
		}

		// Add all pathSegments to tokenPolicies array
		for name, ps := range cp.PathSegments {
			(*pathSegments)[name] = ps
		}
		// Add all "deny" pathSegments to tokenDenyPolicies array
		for name, ps := range cp.DenyPathSegment {
			(*denySegments)[name] = ps
		}
	}
	return msgs, nil
}

// buildAcl creates the ACL from a list of policies
func (r *RequestHandler) buildAcl(ctx context.Context, ctxNs namespace.Namespace, tokenPolicies []*vault.Policy) (*vault.ACL, error) {
	// Contsruct the ACLs
	vCtx := namespace.ContextWithNamespace(ctx, &ctxNs)
	tokenAcl, err := vault.NewACL(vCtx, tokenPolicies)
	if err != nil {
		return nil, errors.Wrap(err, "error building token ACL")
	}
	return tokenAcl, nil
}

// SearchGrantingPolicy searches for a policies (from the entire policy cache) given a path and op
// returns map with structure map[nsPath][policyName]{policy-segment-1, policy-segment-2}
// returns both granting and denying policies
func (r *RequestHandler) searchPolicy(ctx context.Context, path string, op string, requestPathNs namespace.Namespace,
	nsMap map[string]namespace.Namespace) (map[string]map[string][]models.PolicySegment, map[string]map[string][]models.PolicySegment) {
	allowingPolicies := map[string]map[string][]models.PolicySegment{}
	denyingPolicies := map[string]map[string][]models.PolicySegment{}
	r.logger.Debugf("searching policies for %s [%s]", path, op)
	vCtx := namespace.ContextWithNamespace(ctx, &requestPathNs)
	for nsId, cache := range r.policyCache {
		nsPath := nsMap[nsId].Path
		allPolicies := cache.Items()
		for _, cp := range allPolicies {
			cachedPolicy := cp.Object.(*data_cache.CachedPolicy)

			// Search any allowing policies
			aRes := cachedPolicy.Acl.AllowOperation(vCtx, &logical.Request{
				Path:      path,
				Operation: logical.Operation(op),
			}, false)
			if aRes.Allowed {
				// Get the recommended policy names
				for _, gp := range aRes.GrantingPolicies {
					policyName := data_cache.GetPolicyNameFromSegmentName(gp.Name)
					grantingPolicy := models.PolicySegment{
						Raw:  cachedPolicy.PathSegments[gp.Name].Raw,
						Name: gp.Name,
					}
					if _, ok := allowingPolicies[nsPath]; !ok {
						allowingPolicies[nsPath] = map[string][]models.PolicySegment{}
					}
					allowingPolicies[nsPath][policyName] = append(allowingPolicies[nsPath][policyName], grantingPolicy)
				}
			}

			// Search for any denying policies
			dRes := cachedPolicy.DenyAcl.AllowOperation(vCtx, &logical.Request{
				Path:      path,
				Operation: logical.ReadOperation,
			}, false)
			if dRes.Allowed {
				// Get the recommended policy names
				for _, gp := range dRes.GrantingPolicies {
					policyName := data_cache.GetPolicyNameFromSegmentName(gp.Name)
					grantingPolicy := models.PolicySegment{
						Raw:  cachedPolicy.PathSegments[gp.Name].Raw,
						Name: gp.Name,
					}
					if _, ok := denyingPolicies[nsPath]; !ok {
						denyingPolicies[nsPath] = map[string][]models.PolicySegment{}
					}
					denyingPolicies[nsPath][policyName] = append(denyingPolicies[nsPath][policyName], grantingPolicy)
				}
			}
		}
	}
	return allowingPolicies, denyingPolicies
}

// Searches for groups that has a policy (in a namespace)
func (r *RequestHandler) searchGroupWithPolicy(policyName, namespaceId string) (map[string]*vault_helper.Group,
	map[string]*vault_helper.Group, bool, error) {
	groups := map[string]*vault_helper.Group{}
	additionalGroups := map[string]*vault_helper.Group{} // contains additional groups related to the search results (such as parent and member groups)
	cpRaw, found := r.policyCache[namespaceId].Get(policyName)
	if !found {
		r.logger.Error("could not find policy in cache store")
		return groups, additionalGroups, false, nil
	}
	cachedPolicy, ok := cpRaw.(*data_cache.CachedPolicy)
	if !ok {
		r.logger.Error("could not cast to data_cache.CachedPolicy")
		return groups, additionalGroups, found, errors.New("could not cast to data_cache.CachedPolicy")
	}

	gids := cachedPolicy.GroupIds
	for _, gid := range gids {
		groupRaw, found := r.groupCache[namespaceId].Get(gid)
		if !found {
			r.logger.Warn("could not find group with id=" + gid)
			continue
		}
		group, ok := groupRaw.(*vault_helper.Group)
		if !ok {
			r.logger.Error("could not cast to vault_helper.Group id=" + gid)
			return groups, additionalGroups, found, errors.New("could not cast to identity.Group")
		}
		groups[gid] = group

		if len(group.ParentGroupIDs) > 0 {
			for _, parentGid := range group.ParentGroupIDs {
				groupRaw, found := r.groupCache[namespaceId].Get(parentGid)
				if !found {
					r.logger.Warn("could not find group with id=" + parentGid)
					continue
				}
				group, ok := groupRaw.(*vault_helper.Group)
				if !ok {
					r.logger.Error("could not cast to vault_helper.Group id=" + parentGid)
					continue
				}
				additionalGroups[parentGid] = group
			}
		}

		if len(group.MemberGroupIds) > 0 {
			for _, memberGid := range group.MemberGroupIds {
				groupRaw, found := r.groupCache[namespaceId].Get(memberGid)
				if !found {
					r.logger.Warn("could not find group with id=" + memberGid)
					continue
				}
				group, ok := groupRaw.(*vault_helper.Group)
				if !ok {
					r.logger.Error("could not cast to vault_helper.Group id=" + memberGid)
					continue
				}
				additionalGroups[memberGid] = group
			}
		}

	}
	return groups, additionalGroups, true, nil
}

// Searches for auth roles that has a policy (in a namespace)
func (r *RequestHandler) searchAuthRolesWithPolicy(policyName, namespaceId string) (map[string][]data_cache.AuthMountRole, bool, error) {
	cpRaw, found := r.policyCache[namespaceId].Get(policyName)
	if !found {
		r.logger.Error("could not find policy in cache store")
		return map[string][]data_cache.AuthMountRole{}, false, nil
	}
	cachedPolicy, ok := cpRaw.(*data_cache.CachedPolicy)
	if !ok {
		r.logger.Error("could not cast to data_cache.CachedPolicy")
		return map[string][]data_cache.AuthMountRole{}, found, errors.New("could not cast to data_cache.CachedPolicy")
	}
	return cachedPolicy.AuthRoles, true, nil
}
