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

package vault_helper

import (
	"context"
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/identity"
	"github.com/hashicorp/vault/helper/namespace"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"strings"
)

type VaultOperation string

type VaultHelper struct {
	vc       *vault.Client
	loggr    *logrus.Entry
	reqCount int
}

type Group struct {
	identity.Group
	ID              string            `json:"id,omitempty"`
	Name            string            `json:"name,omitempty"`
	Policies        []string          `json:"policies,omitempty"`
	ParentGroupIDs  []string          `json:"parent_group_ids,omitempty"`
	MemberEntityIDs []string          `json:"member_entity_ids,omitempty"`
	MemberGroupIds  []string          `json:"member_group_ids,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	Alias           *identity.Alias   `json:"alias,omitempty"`
	Type            string            `json:"type,omitempty"`
	NamespaceID     string            `json:"namespace_id,omitempty"`
}

func NewVaultHelper(addr string, ns string, token string) (VaultHelper, error) {
	c, err := vault.NewClient(vault.DefaultConfig())
	if err != nil {
		return VaultHelper{}, err
	}
	err = c.SetAddress(addr)
	if err != nil {
		return VaultHelper{}, err
	}
	c.SetNamespace(ns)
	c.SetToken(token)

	logr := logrus.New()
	logr.SetLevel(logrus.DebugLevel)
	return VaultHelper{vc: c, loggr: logr.WithField("namespace", ns)}, nil
}

func (vh *VaultHelper) PrintRequestCount(identifier string) {
	vh.loggr.Infof("\n>> Vault request count [%s] (%s): %d\n", identifier, vh.vc.Namespace(), vh.reqCount)
}

func (vh *VaultHelper) GetNamespace(namespace string) (string, error) {
	vh.reqCount++
	s, e := vh.vc.Logical().Read(fmt.Sprintf("/sys/namespaces/%v", namespace))
	if e != nil {
		return "", e
	}
	vh.loggr.Debug(s)
	return "", nil
}

func SanitiseNamespacePath(namespacePath string) string {
	if namespacePath == "" {
		return namespacePath
	}
	if !strings.HasSuffix(namespacePath, "/") {
		namespacePath += "/"
	}
	return namespacePath
}

// ListNamespaces gets a list of all namespace
// returns map[nsId]namespace
func (vh *VaultHelper) ListNamespaces() (map[string]namespace.Namespace, error) {
	vh.reqCount++
	vh.loggr.Debugf("listing namespaces under %s", vh.vc.Namespace())
	s, e := vh.vc.Logical().List("sys/namespaces")
	if e != nil {
		return nil, e
	}
	nsList := map[string]namespace.Namespace{}
	if s == nil || s.Data == nil {
		return nsList, nil
	}
	nsPaths, ok := s.Data["key_info"].(map[string]interface{})
	if !ok {
		return nsList, errors.New("could not cast key_info into map[string]interface{}")
	}
	for _, infoRaw := range nsPaths {
		info := infoRaw.(map[string]interface{})
		nsId := info["id"].(string)
		nsPath := info["path"].(string)
		var metadata map[string]string
		if info["custom_metadata"] != nil {
			metadataRaw := info["custom_metadata"].(map[string]interface{})
			for key, val := range metadataRaw {
				metadata[key] = val.(string)
			}
		}
		nsList[nsId] = namespace.Namespace{
			ID:             nsId,
			Path:           nsPath,
			CustomMetadata: metadata,
		}
	}
	return nsList, nil
}

// ListNamespaceRecursive recursively gathers all child namespaces under the parent namespaces
// maxDepth is the maximum depth at which the recursion should stop
// a/ -> depth 0
// a/b/ -> depth 1
// a/b/c/ -> depth 2
// -1 for infinte depth
func (vh *VaultHelper) ListNamespaceRecursive(maxDepth int) (map[string]namespace.Namespace, error) {
	ns := map[string]namespace.Namespace{}
	ogNamespace := vh.vc.Namespace()
	ogDepth := strings.Count(ogNamespace, "/") // count number of /, so we know what depth we are at
	vh.loggr.Debug(ogNamespace)
	defer vh.vc.SetNamespace(ogNamespace)

	nsQueue := []string{vh.vc.Namespace()} // depth 0
	for len(nsQueue) != 0 {
		currentParentNs := nsQueue[0]
		nsQueue = nsQueue[1:] // pop it off the queue
		vh.vc.SetNamespace(currentParentNs)
		nsList, err := vh.ListNamespaces()
		if err != nil {
			return ns, err
		}
		for _, nsInfo := range nsList {
			ns[nsInfo.ID] = nsInfo
			if maxDepth == -1 || strings.Count(nsInfo.Path, "/")-ogDepth < maxDepth { // check if it passes maxDepth
				nsQueue = append(nsQueue, nsInfo.Path)
			}
		}
	}

	return ns, nil
}

func (vh *VaultHelper) TokenLookupSelf() (map[string]interface{}, error) {
	vh.reqCount++
	s, e := vh.vc.Auth().Token().LookupSelf()
	if e != nil {
		return nil, e
	}
	return s.Data, nil
}

func (vh *VaultHelper) TokenLookup(token string) (map[string]interface{}, error) {
	vh.reqCount++
	s, e := vh.vc.Auth().Token().Lookup(token)
	if e != nil {
		return nil, e
	}
	return s.Data, nil
}

func (vh *VaultHelper) TokenLookupAccessor(accessor string) (map[string]interface{}, error) {
	vh.reqCount++
	//vh.loggr.Debug("looking up accessor " + accessor)
	s, e := vh.vc.Auth().Token().LookupAccessor(accessor)
	if e != nil {
		return nil, e
	}
	return s.Data, nil
}

func (vh *VaultHelper) ListAllGroupIds() ([]string, error) {
	vh.reqCount++
	groupIds := []string{}
	s, e := vh.vc.Logical().List("identity/group/id")
	if e != nil {
		return groupIds, errors.Wrap(e, "error fetching all groups")
	}
	if s == nil || s.Data == nil {
		return groupIds, nil
	}
	gidsRaw, ok := s.Data["keys"].([]interface{})
	if !ok {
		return groupIds, errors.New("error getting 'keys' from response")
	}
	for _, gid := range gidsRaw {
		groupIds = append(groupIds, gid.(string))
	}
	return groupIds, nil
}

func (vh *VaultHelper) FetchGroupById(id string) (Group, error) {
	vh.reqCount++
	s, e := vh.vc.Logical().Read("/identity/group/id/" + id)
	if e != nil {
		return Group{}, errors.Wrap(e, "error fetching all groups")
	}

	policies := []string{}
	if s.Data["policies"] != nil {
		for _, p := range s.Data["policies"].([]interface{}) {
			policies = append(policies, p.(string))
		}
	}
	parentGroupIds := []string{}
	if s.Data["parent_group_ids"] != nil {
		for _, pgi := range s.Data["parent_group_ids"].([]interface{}) {
			parentGroupIds = append(parentGroupIds, pgi.(string))
		}
	}
	memberGroupIds := []string{}
	if s.Data["member_group_ids"] != nil {
		for _, mei := range s.Data["member_group_ids"].([]interface{}) {
			memberGroupIds = append(memberGroupIds, mei.(string))
		}
	}
	memberEntityIds := []string{}
	if s.Data["member_entity_ids"] != nil {
		for _, mei := range s.Data["member_entity_ids"].([]interface{}) {
			memberEntityIds = append(memberEntityIds, mei.(string))
		}
	}
	metadata := map[string]string{}
	if s.Data["metadata"] != nil {
		for k, v := range s.Data["metadata"].(map[string]interface{}) {
			metadata[k] = v.(string)
		}
	}

	var alias *identity.Alias
	// Parse the alias
	if s.Data["alias"] != nil {
		a := identity.Alias{}
		for k, v := range s.Data["alias"].(map[string]interface{}) {
			switch k {
			case "canonical_id":
				a.CanonicalID = v.(string)
			case "id":
				a.ID = v.(string)
			case "name":
				a.Name = v.(string)
			case "mount_accessor":
				a.MountAccessor = v.(string)
			case "mount_path":
				a.MountPath = v.(string)
			case "mount_type":
				a.MountType = v.(string)
			}
		}
		alias = &a
	}
	return Group{
		ID:              id,
		Name:            s.Data["name"].(string),
		Policies:        policies,
		ParentGroupIDs:  parentGroupIds,
		MemberEntityIDs: memberEntityIds,
		MemberGroupIds:  memberGroupIds,
		Metadata:        metadata,
		Alias:           alias,
		Type:            s.Data["type"].(string),
	}, nil
}

func (vh *VaultHelper) FetchAllGroups() (map[string]*Group, error) {
	vh.loggr.Debugf("fetching groups under %s", vh.vc.Namespace())

	vh.loggr.Debugf("listing groups under %s", vh.vc.Namespace())
	groupIds, err := vh.ListAllGroupIds()
	if err != nil {
		return map[string]*Group{}, errors.Wrap(err, "error listing group ids")
	}

	groups := map[string]*Group{}
	for i, groupId := range groupIds {
		vh.loggr.Debugf("[%d/%d] fetching group %s", i, len(groupIds), groupId)
		g, err := vh.FetchGroupById(groupId)
		if err != nil {
			return groups, errors.Wrap(err, "error fetching group with id "+groupId)
		}

		groups[groupId] = &g
	}

	return groups, nil
}

func (vh *VaultHelper) FetchAllPolicies(ctx context.Context) (map[string]string, error) {
	vh.reqCount++
	policies := map[string]string{}
	policyNames, err := vh.vc.Sys().ListPoliciesWithContext(ctx)
	if err != nil {
		return policies, errors.Wrap(err, "error fetching all policies")
	}

	for i, policyName := range policyNames {
		vh.loggr.Debugf("fetching policy [%d/%d]: %s", i+1, len(policyNames), policyName)
		policy, err := vh.FetchPolicy(policyName)
		if err != nil {
			return policies, errors.Wrap(err, "error fetching policy: "+policyName)
		}
		policies[policyName] = policy
	}

	return policies, nil
}

func (vh *VaultHelper) FetchPolicy(policyName string) (string, error) {
	vh.reqCount++
	policy, err := vh.vc.Sys().GetPolicy(policyName)
	if err != nil {
		return "", err
	}
	return policy, nil
}

func (vh *VaultHelper) FetchPoliciesFromAuthRole(path string, role string) ([]string, error) {
	vh.reqCount++
	policies := []string{}
	s, e := vh.vc.Logical().Read("auth/" + path + "role/" + role)
	if e != nil {
		return policies, errors.Wrap(e, "error fetching role")
	}
	policiesRaw, ok := s.Data["token_policies"].([]interface{})
	if !ok {
		return policies, errors.New("error getting 'token_policies' from response")
	}
	for _, r := range policiesRaw {
		policies = append(policies, r.(string))
	}
	return policies, nil

}

func (vh *VaultHelper) ListAuthRoles(path string) ([]string, error) {
	roles := []string{}
	vh.reqCount++
	s, e := vh.vc.Logical().List("auth/" + path + "/role")
	if e != nil {
		return roles, errors.Wrap(e, "error fetching all roles")
	}
	if s == nil || s.Data == nil {
		return roles, nil
	}
	rolesRaw, ok := s.Data["keys"].([]interface{})
	if !ok {
		return roles, errors.New("error getting 'keys' from response")
	}
	for _, r := range rolesRaw {
		roles = append(roles, r.(string))
	}
	return roles, nil
}

func (vh *VaultHelper) ListAllAuthMounts() (map[string]vault.AuthMount, error) {
	authMounts := map[string]vault.AuthMount{}
	vh.reqCount++
	s, e := vh.vc.Logical().Read("sys/auth")
	if e != nil {
		return authMounts, errors.Wrap(e, "error fetching all auth mounts")
	}
	if s == nil || s.Data == nil {
		return authMounts, nil
	}
	for path, mp := range s.Data {
		authMnt, ok := mp.(map[string]interface{})
		if !ok {
			continue
		}
		authMounts[path] = vault.AuthMount{
			UUID:                  authMnt["uuid"].(string),
			Type:                  authMnt["type"].(string),
			Description:           authMnt["description"].(string),
			Accessor:              authMnt["accessor"].(string),
			Local:                 authMnt["local"].(bool),
			SealWrap:              authMnt["seal_wrap"].(bool),
			ExternalEntropyAccess: authMnt["external_entropy_access"].(bool),
			PluginVersion:         authMnt["plugin_version"].(string),
			RunningVersion:        authMnt["running_plugin_version"].(string),
		}
	}
	return authMounts, nil
}
