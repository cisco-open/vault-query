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

package data_cache

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/vault"
	gocache "github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"
	"vaultquery/pkg/common"
	vault_helper "vaultquery/pkg/vault-helper"
)

type VaultCache struct {
	RefreshInterval time.Duration
	VaultAddress    string
	VaultToken      string
	PolicyStore     map[string]*gocache.Cache
	GroupStore      map[string]*gocache.Cache

	logr *logrus.Entry
}

type CachedPolicy struct {
	Policy          *vault.Policy
	Acl             *vault.ACL                 // ACL of the path segments
	DenyAcl         *vault.ACL                 // ACL of the deny path segments
	GroupIds        []string                   // Group Ids that have this policy
	AuthRoles       map[string][]AuthMountRole // Auth roles that have this policy - map[authType][]{role1, role2}
	PathSegments    map[string]*vault.Policy   // Holds path segments of the policy as list of separate policies - map[segmentName]Policy
	DenyPathSegment map[string]*vault.Policy   // Holds path segments that have deny capability, as list of separate policies - map[segmentName]Policy
}

type AuthMountRole struct {
	MountPath string
	Role      string
	Type      string
}

const DefaultCacheRefresh = 1 * time.Minute

// Start populates the cache store
// also starts the syncing process
// expects a list of namespaces to sync policies from
// expects a metadata cache to store metadata about the syncing process
func (vc *VaultCache) Start(ctx context.Context, namespaces map[string]namespace.Namespace, metadata *gocache.Cache) error {

	vc.PolicyStore = map[string]*gocache.Cache{}
	vc.GroupStore = map[string]*gocache.Cache{}
	if vc.logr == nil {
		vc.logr = logrus.WithField("routine", "data-cache")
	}

	if vc.RefreshInterval == 0 {
		vc.RefreshInterval = 1 * time.Minute
	}

	vc.logr.Debug(namespaces)

	// For each namespace sync the policies and start a new routine to periodically download
	for _, ns := range namespaces {
		expirationTime := vc.RefreshInterval * 2
		cleanupInterval := vc.RefreshInterval * 3
		// initialise the cache for the namespace
		vc.PolicyStore[ns.ID] = gocache.New(expirationTime, cleanupInterval)
		vc.GroupStore[ns.ID] = gocache.New(expirationTime, cleanupInterval)
		vc.logr.Debugf("intevals [%s] - refresh: %v, expiration: %v, cleanup: %v", ns.Path, vc.RefreshInterval, expirationTime, cleanupInterval)

		vc.GroupStore[ns.ID].OnEvicted(func(s string, i interface{}) {
			vc.logr.Debugf("group evicted for namesapce %s, policy: %s", ns.Path, s)
		})
		vc.PolicyStore[ns.ID].OnEvicted(func(s string, i interface{}) {
			vc.logr.Debugf("policy evicted for namesapce %s, policy: %s", ns.Path, s)
		})

		timerChan := time.NewTicker(vc.RefreshInterval)
		//rand.Seed(time.Now().UnixNano()) // Done automatically in Go 1.20+

		vc.logr.Debug(fmt.Sprintf("starting policy downloader for namespace %s", ns))
		err := vc.syncPolicies(ctx, vc.PolicyStore[ns.ID], ns, vc.VaultAddress, vc.VaultToken)
		if err != nil {
			vc.logr.Errorf("error syncing policies: %v", err)
		}
		err = vc.syncGroups(vc.GroupStore[ns.ID], vc.PolicyStore[ns.ID], ns, vc.VaultAddress, vc.VaultToken)
		if err != nil {
			vc.logr.Errorf("error syncing groups: %v", err)
		}
		err = vc.syncAuthMounts(vc.PolicyStore[ns.ID], ns, vc.VaultAddress, vc.VaultToken)
		if err != nil {
			vc.logr.Errorf("error syncing auth mounts: %v", err)
		}

		metadata.Set(ns.Path+common.CacheReadyKey, time.Now(), gocache.NoExpiration) // set initialised to true - so the other threads know

		// Start the policy syncing loop
		firstIteration := true
		go func(vaultNs namespace.Namespace, vaultAddr, vaultToken string) {
			logr := logrus.WithField("routine", "policy-sync").WithField("namespace", vaultNs.Path)
			logr.Debug("starting policy sync routine")
			for {
				select {
				case <-timerChan.C: // Watch for ticker
					if firstIteration {
						// Put a random delay
						// this is so the policy syncing for different namespaces are staggered
						upper := int(vc.RefreshInterval / 2)
						lower := int(vc.RefreshInterval / 100)
						randomTime := rand.Intn(upper) + lower
						logr.Debugf("sleeping (for %s) to stagger policy downloads", time.Duration(randomTime))
						time.Sleep(time.Duration(randomTime))
						firstIteration = false
					}
					logr.Debug("timer tick: syncing policies...")
					err := vc.syncPolicies(ctx, vc.PolicyStore[vaultNs.ID], vaultNs, vaultAddr, vaultToken)
					if err != nil {
						logr.Errorf("error syncing policies %v", err)
					}
					err = vc.syncGroups(vc.GroupStore[vaultNs.ID], vc.PolicyStore[vaultNs.ID], vaultNs, vc.VaultAddress, vc.VaultToken)
					if err != nil {
						logr.Errorf("error syncing groups %v", err)
					}
					err = vc.syncAuthMounts(vc.PolicyStore[vaultNs.ID], vaultNs, vc.VaultAddress, vc.VaultToken)
					if err != nil {
						logr.Errorf("error syncing auth mounts %v", err)
					}
					metadata.Set(vaultNs.Path+common.CacheReadyKey, time.Now(), gocache.NoExpiration)
				case <-ctx.Done(): // Watch for cancellation signal
					return
				}
			}
		}(ns, vc.VaultAddress, vc.VaultToken)
	}

	vc.logr.Debug("initial syncing done, timers started")
	return nil
}

// syncPolicies downloads all policies in a namespace and parses them, and stores them in a cache
func (vc *VaultCache) syncPolicies(ctx context.Context, policyCache *gocache.Cache,
	vaultNs namespace.Namespace, vaultAddr, vaultToken string) error {
	vc.logr.Debug("syncing policies for namespace ", vaultNs.Path)
	vh, err := vault_helper.NewVaultHelper(vaultAddr, vaultNs.Path, vaultToken)
	if err != nil {
		return errors.Wrap(err, "error creating Vault Helper")
	}

	rawPolicies, err := vh.FetchAllPolicies(ctx)
	if err != nil {
		return errors.Wrap(err, "error getting all policies")
	}

	for policyName, policy := range rawPolicies {
		vc.logr.Debug("parsing policy ", policyName)
		cp, err := ParsePolicy(ctx, policyName, policy, vaultNs)
		if err != nil { // log the error and continue parsing other policies
			vc.logr.Errorf("error parsing policy: %s; %v", policyName, err)
		}
		policyCache.Set(policyName, cp, gocache.DefaultExpiration)
	}

	vh.PrintRequestCount("policy")
	return nil
}

// syncGroups downloads all groups in a namespace, and stores them in a cache
func (vc *VaultCache) syncGroups(groupCache *gocache.Cache, policyCache *gocache.Cache,
	vaultNs namespace.Namespace, vaultAddr, vaultToken string) error {
	vc.logr.Debug("syncing policies for namespace ", vaultNs.Path)
	vh, err := vault_helper.NewVaultHelper(vaultAddr, vaultNs.Path, vaultToken)
	if err != nil {
		return errors.Wrap(err, "error creating Vault Helper")
	}

	groups, err := vh.FetchAllGroups()
	if err != nil {
		return errors.Wrap(err, "error getting all policies")
	}

	for groupId, g := range groups {
		groupCache.Set(groupId, g, gocache.DefaultExpiration)
		for _, policyName := range g.Policies {
			p, ok := policyCache.Get(policyName)
			if !ok {
				continue
			}
			cp := p.(*CachedPolicy)
			cp.GroupIds = append(cp.GroupIds, groupId)
			policyCache.Set(policyName, cp, gocache.DefaultExpiration)
		}
	}
	vh.PrintRequestCount("groups")
	return nil
}

// syncAuthMounts downloads all auth mount roles in a namespace, and stores them in a cache
func (vc *VaultCache) syncAuthMounts(policyCache *gocache.Cache, vaultNs namespace.Namespace, vaultAddr, vaultToken string) error {
	vc.logr.Debug("syncing auth mounts for namespace ", vaultNs.Path)
	vh, err := vault_helper.NewVaultHelper(vaultAddr, vaultNs.Path, vaultToken)
	if err != nil {
		return errors.Wrap(err, "error creating Vault Helper")
	}

	authMnts, err := vh.ListAllAuthMounts()
	if err != nil {
		return errors.Wrap(err, "error listing auth mounts")
	}

	// fetch the auth mounts
	for path, am := range authMnts {
		if am.Type == "oidc" || am.Type == "approle" { // we only look for oidc and approle types
			roles, err := vh.ListAuthRoles(path)
			if err != nil {
				return errors.Wrap(err, "error listing auth roles for path: "+path)
			}
			// fetch the roles for each auth mount
			for _, role := range roles {
				policies, err := vh.FetchPoliciesFromAuthRole(path, role)
				if err != nil {
					return errors.Wrapf(err, "error fetching policies for path:%s , role: %s", path, role)
				}

				// for each policy of that role, update the policy in cache to reference this role
				for _, policyName := range policies {
					p, ok := policyCache.Get(policyName)
					if !ok {
						continue
					}
					cp := p.(*CachedPolicy)
					cp.AuthRoles[am.Type] = append(cp.AuthRoles[am.Type], AuthMountRole{
						MountPath: path,
						Role:      role,
						Type:      am.Type,
					})
					policyCache.Set(policyName, cp, gocache.DefaultExpiration)
				}
			}
		}
	}
	vh.PrintRequestCount("auth")
	return nil
}

// ParsePolicy takes a raw policy and does the following:
//   - segment the policy into its paths and create a new policy for each
//   - if the segment has deny, create another new policy (and change it to read)
//   - create an ACL with the path segment policies
//   - create an ACL with the deny path segment policies
func ParsePolicy(cCtx context.Context, policyName string, policyString string, ns namespace.Namespace) (*CachedPolicy, error) {
	policy := &CachedPolicy{
		Policy:          nil,
		Acl:             nil,
		DenyAcl:         nil,
		GroupIds:        []string{},
		AuthRoles:       map[string][]AuthMountRole{},
		PathSegments:    nil,
		DenyPathSegment: nil,
	}

	ctx := namespace.ContextWithNamespace(cCtx, &ns)

	// Parse the policy with vault pkgs
	aclPolicy, err := vault.ParseACLPolicy(&ns, policyString)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing ACL policy")
	}
	aclPolicy.Name = policyName // we need to set this explicitly
	policy.Policy = aclPolicy   // Set the parsed policy to the struct

	pathSegments := map[string]*vault.Policy{}
	denySegments := map[string]*vault.Policy{}

	// Create a policy for each path segment
	// The reason we do this is to see exactly which path in the policy is responsible for granting access
	for idx, path := range aclPolicy.Paths {
		ps := aclPolicy.ShallowClone() // Create a new policy from the main policy
		ps.Name = generateSegmentNameFromPolicy(policy.Policy, strconv.Itoa(idx))
		ps.Paths = []*vault.PathRules{path}
		capString, _ := json.Marshal(path.Capabilities)
		// Generate the raw policy segment
		raw := ""
		cleanPath, _ := strings.CutPrefix(path.Path, ns.Path) // remove the namespace prefix from the path
		if path.IsPrefix {                                    // check if it has a wild card '*'
			raw = fmt.Sprintf("path \"%s*\" {\n\tcapabilities=%v\n}", cleanPath, string(capString))
		} else {
			raw = fmt.Sprintf("path \"%s\" {\n\tcapabilites=%v\n}", cleanPath, string(capString))
		}
		ps.Raw = raw
		pathSegments[ps.Name] = ps
		// If the path contains deny, we create a new policy and change that deny to "read"
		// This is a hack - its so when a path gets denied, we can try to trace back which policy segment is denying
		if path.Permissions.CapabilitiesBitmap&1 == 1 {
			dps := ps.ShallowClone()
			denyPath := vault.PathRules{
				Path:   path.Path,
				Policy: path.Policy,
				Permissions: &vault.ACLPermissions{
					CapabilitiesBitmap: vault.ReadCapabilityInt, // Change deny to read
				},
				IsPrefix:            path.IsPrefix,
				HasSegmentWildcards: path.HasSegmentWildcards,
				Capabilities:        []string{vault.ReadCapability},
			}
			dps.Paths = []*vault.PathRules{&denyPath}
			denySegments[dps.Name] = dps
		}

	}

	policy.PathSegments = pathSegments
	policy.DenyPathSegment = denySegments

	// Get slice of path segments from map
	pss := make([]*vault.Policy, 0, len(policy.PathSegments))
	for _, v := range policy.PathSegments {
		pss = append(pss, v)
	}
	// Get slice of deny path segments from map
	dpss := make([]*vault.Policy, 0, len(policy.DenyPathSegment))
	for _, v := range policy.DenyPathSegment {
		dpss = append(dpss, v)
	}

	acl, err := vault.NewACL(ctx, pss)
	if err != nil {
		return policy, errors.Wrap(err, "error creating ACL from path segments")
	}
	denyAcl, err := vault.NewACL(ctx, dpss)
	if err != nil {
		return policy, errors.Wrap(err, "error creating ACL from deny path segments")
	}

	policy.Acl = acl
	policy.DenyAcl = denyAcl

	return policy, nil
}

func (vc *VaultCache) quit(code int) {
	vc.logr.Warning("exiting...")
	os.Exit(code)
}

func generateSegmentNameFromPolicy(policy *vault.Policy, id string) string {
	return policy.Name + "/" + id
}

func GetPolicyNameFromSegmentName(pathSegmentName string) string {
	idx := strings.LastIndex(pathSegmentName, "/")
	return pathSegmentName[:idx]
}
