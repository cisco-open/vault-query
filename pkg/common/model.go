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

package common

//
//import "github.com/hashicorp/vault/vault"
//
//type VaultPath struct {
//	Path       string `json:"path"`
//	HttpMethod string `json:"httpMethod"`
//	Namespace  string `json:"namespace"`
//	Extras     map[string]interface{}
//}
//
//type VaultTokenDetails struct {
//	IdentityPolicies          []string            `json:"identityPolicies"`
//	ExternalNamespacePolicies map[string][]string `json:"externalNamespacePolicies"`
//	Policies                  []string            `json:"policies"`
//	NamespacePath             string              `json:"namespacePath"`
//}
//
//type AclData struct {
//	Allowed             bool                    `json:"allowed"`
//	GrantingPolicies    map[string]vault.Policy `json:"grantingPolicies"`
//	CapabilitiesGranted []string                `json:"grantedCapabilities"`
//	DenyingPolicies     map[string]vault.Policy `json:"denyingPolicies"`
//	RecommendedPolicies []string                `json:"recommendedPolicies"`
//	TokenPolicies       []*vault.Policy         `json:"tokenPolicies"`
//}
//
//type Request struct {
//	Id               string    `json:"id"` // not used by client
//	VaultPathDetails VaultPath `json:"pathDetails"`
//	//VaultTokenDetails VaultTokenDetails `json:"tokenDetails"`
//	//EnvVars           map[string]string `json:"envVars"`
//}
//
//type Response struct {
//	Id       string    `json:"id"`
//	Findings []Finding `json:"findings"`
//}
