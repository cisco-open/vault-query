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

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"vaultquery/models"
	aclient "vaultquery/pkg/apiclinet/auth"
	gclient "vaultquery/pkg/apiclinet/group"
	pclient "vaultquery/pkg/apiclinet/policy"
	"vaultquery/pkg/common"
	data_cache "vaultquery/pkg/data-cache"
	"vaultquery/pkg/trie"
	vault_helper "vaultquery/pkg/vault-helper"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/hashicorp/vault/vault"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2" // imports as package "cli"
	"gopkg.in/yaml.v3"
)

/*

check-path
tree
get-policy
get-groups-by-policy
get-auths-by-policy

analyze (can also be triggered from pipe)
 - check path and op
 - check which policies give that access
 - check which groups give access
 - check with auth give access

*/

type DefaultConfig struct {
	Server        string `yaml:"server"`
	NoTLS         bool   `yaml:"noTLS"`
	NoTokenHelper bool   `yaml:"noTokenHelper"`
}

const ConfigPath = ".config/vault-query/config.yaml"

var vaultPath string
var vaultOperation string
var vaultPathNamespace string
var serverUrl string
var noTLS bool
var treePrefix string
var accessor string
var namespace string
var noTokenHelper bool
var noTokenPolicies bool
var customPolicyFile string
var customPolicyNamespace string
var vaultPolicies cli.StringSlice
var version string

func main() {
	// Load up config file if it exists
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Println(textErr.Margin(0).Render(fmt.Sprintf("Error reading user home: %v", err)))
		return
	}
	fullConfigPath := home + "/" + ConfigPath
	if _, err := os.Stat(fullConfigPath); !errors.Is(err, os.ErrNotExist) {
		fmt.Printf("Reading from config file (%s)\n", fullConfigPath)
		yamlFile, err := os.ReadFile(fullConfigPath)
		if err != nil {
			fmt.Println(textErr.Margin(0).Render(fmt.Sprintf("Error loading default config file (%s): %v", fullConfigPath, err)))
			return
		}
		defaults := DefaultConfig{}
		err = yaml.Unmarshal(yamlFile, &defaults)
		if err != nil {
			fmt.Println(textErr.Margin(0).Render(fmt.Sprintf("Error unmarshalling default config file (%s): %v", fullConfigPath, err)))
			return
		}
		noTokenHelper = defaults.NoTokenHelper
		noTLS = defaults.NoTLS
		serverUrl = defaults.Server
	} else {
		fmt.Println(textWarn.MarginTop(1).MarginLeft(2).Render(
			fmt.Sprintf("* Warning: No config file found in %s\n", fullConfigPath)))
	}

	app := &cli.App{
		Name: "vault-query",
		Usage: `vault-query provides a interface to query vault policies and groups
Example usages:

vq analyze -p secret/data/foo/bar -o create -ns foopaas                       # Analyzes given path and method with your token
vq analyze --po test-policy -p secret/data/foo/bar -o read -ns foopaas   	 # To analyze with a specific policy
vq analyze --accessor abc123 -p secret/data/foo/bar -o create -ns foopaas 	 # To analyze with a token accessor
vault kv get secret/foo/infra 2>&1 | vq                  	 # You can also pipe in vault errors to generate what commands to run
`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "host",
				Value:       serverUrl,
				Destination: &serverUrl,
				Usage:       "url for the vault-query server",
			},
			&cli.BoolFlag{
				Name:        "no-tls",
				Value:       noTLS,
				Destination: &noTLS,
				Usage:       "doesn't use TLS when connecting to server",
			},
			&cli.BoolFlag{
				Name:        "no-token-helper",
				Aliases:     []string{"no-th"},
				Value:       noTokenHelper,
				Destination: &noTokenHelper,
				Usage:       "uses env vars instead of token helper, by default it will use token-helper if detected",
			},
		},
		Commands: []*cli.Command{
			{
				Name:    "version",
				Aliases: []string{"v"},
				Usage:   "Show version of the app",
				Action: func(cCtx *cli.Context) error {
					fmt.Println(version)
					return nil
				},
			},
			{
				Name:    "analyze",
				Aliases: []string{"an"},
				Usage:   "(interactive) checks if a path is allowed, then based on user input, finds policies and groups",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "path",
						Aliases:     []string{"p"},
						Value:       "",
						Destination: &vaultPath,
						Usage:       "vault path that is being accessed, e.g. secret/data/my/secret",
					},
					&cli.StringFlag{
						Name:        "operation",
						Aliases:     []string{"o"},
						Value:       "",
						Destination: &vaultOperation,
						Usage:       "The operation that needs to be performed e.g. create",
					},
					&cli.StringFlag{
						Name:        "namespace",
						Aliases:     []string{"ns"},
						Value:       "",
						Destination: &vaultPathNamespace,
						Usage:       "The namespace in which the path is being accessed",
					},
					&cli.StringSliceFlag{
						Name:        "policy",
						Destination: &vaultPolicies,
						Usage:       "Policies to evaluate the request with. Format <ns>:<policy-name>, e.g. --policy foopaas:admin --policy rootns/foopaas:foo",
					},
					&cli.StringFlag{
						Name:        "accessor",
						Destination: &accessor,
						Usage:       "If provided, uses the the details from the accessor instead of the token, e.g. --accessor abcd1234",
					},
					&cli.BoolFlag{
						Name:        "no-token-policies",
						Destination: &noTokenPolicies,
						Usage:       "If set, token (or accessor) policies will not be sent to the server to evaluate",
					},
				},
				Action: func(cCtx *cli.Context) error {
					// Parse the explicit policy names (into map[namespace][]{policyNames}
					policies := map[string][]string{}
					for _, p := range vaultPolicies.Value() {
						v := strings.SplitN(p, ":", 2)
						if len(v) < 2 {
							fmt.Println(textErr.Margin(0).Render(fmt.Sprintf("Error: policies must be passed in as <namespace>:<policy-name> e.g. ns-a:policy-a")))
							return nil
						}
						policies[v[0]] = append(policies[v[0]], v[1])
					}

					// Get token details
					tokenDetails, token, err := getTokenDetails(accessor)
					if err != nil {
						fmt.Println(textErr.Margin(0).Render("Error: ", err.Error()))
						return nil
					}
					err = validateVaultOp(strings.ToLower(vaultOperation))
					if err != nil {
						fmt.Println(textErr.Margin(0).Render("Error: ", err.Error()))
						return nil
					}
					analyze(cCtx.Context, vaultPath, strings.ToLower(vaultOperation), vaultPathNamespace, policies, token, tokenDetails)
					return nil
				},
			},
			{
				Name:    "check-allowed",
				Aliases: []string{"chk"},
				Usage:   "checks whether a path is allowed e.g. vq check-path -p secret/data/foo -o create -ns foopaas/dev",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "path",
						Aliases:     []string{"p"},
						Value:       "",
						Destination: &vaultPath,
						Usage:       "vault path that is being accessed, e.g. secret/data/my/secret",
					},
					&cli.StringFlag{
						Name:        "operation",
						Aliases:     []string{"o"},
						Value:       "",
						Destination: &vaultOperation,
						Usage:       "The operation that needs to be performed e.g. create",
					},
					&cli.StringFlag{
						Name:        "namespace",
						Aliases:     []string{"ns"},
						Value:       "",
						Destination: &vaultPathNamespace,
						Usage:       "The namespace in which the path is being accessed",
					},
					&cli.StringSliceFlag{
						Name:        "policy",
						Destination: &vaultPolicies,
						Usage:       "Policies to evaluate the request with. Format <ns>:<policy-name>, e.g. --policy foopaas:admin --policy foopaas/dev:foo",
					},
					&cli.StringFlag{
						Name:        "accessor",
						Destination: &accessor,
						Usage:       "If provided, uses the the details from the accessor instead of the token, e.g. --accessor abcd1234",
					},
					&cli.StringFlag{
						Name:        "custom-policy-file",
						Destination: &customPolicyFile,
						Usage:       "Can be used to pass in custom policy to the server to evaluate the request against",
					},
					&cli.StringFlag{
						Name:        "custom-policy-namespace",
						Destination: &customPolicyNamespace,
						Usage:       "namespace in which the custom policy will reside in",
					},
					&cli.BoolFlag{
						Name:        "no-token-policies",
						Destination: &noTokenPolicies,
						Usage:       "If set, token (or accessor) policies will not be sent to the server to evaluate",
					},
				},
				Action: func(cCtx *cli.Context) error {
					// Parse the explicit policy names (into map[namespace][]{policyNames}
					policies := map[string][]string{}
					for _, p := range vaultPolicies.Value() {
						v := strings.SplitN(p, ":", 2)
						if len(v) < 2 {
							fmt.Println(textErr.Margin(0).Render(fmt.Sprintf("Error: policies must be passed in as <namespace>:<policy-name> e.g. ns-a:policy-a")))
							return nil
						}
						policies[v[0]] = append(policies[v[0]], v[1])
					}

					// Get custom policy details
					customPolicy, err := getCustomPolicies()
					if err != nil {
						fmt.Println(textErr.Margin(0).Render("Error: ", err.Error()))
						return nil
					}

					// Get token details
					tokenDetails, token, err := getTokenDetails(accessor)
					if err != nil {
						fmt.Println(textErr.Margin(0).Render("Error: ", err.Error()))
						return nil
					}

					err = validateVaultOp(strings.ToLower(vaultOperation))
					if err != nil {
						fmt.Println(textErr.Margin(0).Render("Error: ", err.Error()))
						return nil
					}
					_ = checkAllowed(cCtx.Context, vaultPath, strings.ToLower(vaultOperation), vaultPathNamespace, customPolicy, policies, token, tokenDetails)
					if err != nil {
						fmt.Println(textErr.Margin(0).Render("Error: ", err.Error()))
						return nil
					}
					return nil
				},
			},
			// Tree command generates a tree from policies
			{
				Name:  "tree",
				Usage: "outputs a tree using the vault policies in your token e.g. wvw tree",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "prefix",
						Value:       "",
						Destination: &treePrefix,
						Usage:       "prefix from where to start the tree, e.g. wvw tree --prefix=foopaas/dev",
					},
					&cli.StringSliceFlag{
						Name:        "policy",
						Aliases:     []string{"po"},
						Destination: &vaultPolicies,
						Usage:       "If set the policies set with this flag will be used instead of the one in token, e.g. --policy foo --policy bar",
					},
					&cli.StringFlag{
						Name:        "accessor",
						Destination: &accessor,
						Usage:       "If provided, uses the the details from the accessor instead of the token, e.g. --accessor abcd1234",
					},
					&cli.StringFlag{
						Name:        "custom-policy-file",
						Destination: &customPolicyFile,
						Usage:       "Can be used to pass in custom policy to the server to evaluate the request against",
					},
					&cli.StringFlag{
						Name:        "custom-policy-namespace",
						Destination: &customPolicyNamespace,
						Usage:       "namespace in which the custom policy will reside in",
					},
					&cli.BoolFlag{
						Name:        "no-token-policies",
						Destination: &noTokenPolicies,
						Usage:       "If set, token (or accessor) policies will not be sent to the server to evaluate",
					},
				},
				Action: func(cCtx *cli.Context) error {
					// Parse the explicit policy names (into map[namespace][]{policyNames}
					policies := map[string][]string{}
					for _, p := range vaultPolicies.Value() {
						v := strings.SplitN(p, ":", 2)
						if len(v) < 2 {
							fmt.Println(textErr.Margin(0).Render(fmt.Sprintf("Error: policies must be passed in as <namespace>:<policy-name> e.g. ns-a:policy-a")))
							return nil
						}
						policies[v[0]] = append(policies[v[0]], v[1])
					}

					// Get custom policy details
					customPolicy, err := getCustomPolicies()
					if err != nil {
						fmt.Println(textErr.Margin(0).Render("Error: ", err.Error()))
						return nil
					}

					// Get token details
					tokenDetails, token, err := getTokenDetails(accessor)
					if err != nil {
						fmt.Println(textErr.Margin(0).Render("Error: ", err.Error()))
						return nil
					}

					tree(cCtx.Context, treePrefix, customPolicy, policies, token, tokenDetails)
					if err != nil {
						fmt.Println(textErr.Margin(0).Render("Error: ", err.Error()))
					}
					return nil
				},
			},
			// Get Policy gets a policy from server
			{
				Name:    "get-policy",
				Aliases: []string{"gp"},
				Usage:   "fetches details of a policy",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "namespace",
						Aliases:     []string{"ns"},
						Destination: &namespace,
						Usage:       "namespace of the policy",
						Required:    true,
					},
				},
				Action: func(cCtx *cli.Context) error {
					_, token, err := getTokenDetails(accessor)
					if err != nil {
						fmt.Println(textErr.Margin(0).Render("Error: ", err.Error()))
						return nil
					}
					_ = getPolicy(cCtx.Context, cCtx.Args().Get(0), namespace, token)
					if err != nil {
						fmt.Println(textErr.Margin(0).Render("Error: ", err.Error()))
						return nil
					}
					return nil
				},
			},
			// Get groups that contain a policy from server
			{
				Name:    "search-groups-by-policy",
				Aliases: []string{"sgp"},
				Usage:   "fetches groups that have a policy",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "namespace",
						Aliases:     []string{"ns"},
						Destination: &namespace,
						Usage:       "namespace of the policy",
						Required:    true,
					},
				},
				Action: func(cCtx *cli.Context) error {
					_, token, err := getTokenDetails(accessor)
					if err != nil {
						fmt.Println(textErr.Margin(0).Render("Error: ", err.Error()))
						return nil
					}
					_ = searchGroupsByPolicy(cCtx.Context, cCtx.Args().Get(0), namespace, token)
					if err != nil {
						fmt.Println(textErr.Margin(0).Render("Error: ", err.Error()))
						return nil
					}
					return nil
				},
			},
			// Get Auth methods that have a policy from server
			{
				Name:    "search-auth-by-policy",
				Aliases: []string{"sap"},
				Usage:   "fetches auth roles that have a policy",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "namespace",
						Aliases:     []string{"ns"},
						Destination: &namespace,
						Usage:       "namespace of the policy",
						Required:    true,
					},
				},
				Action: func(cCtx *cli.Context) error {
					_, token, err := getTokenDetails(accessor)
					if err != nil {
						fmt.Println(textErr.Margin(0).Render("Error: ", err.Error()))
						return nil
					}
					_ = searchAuthRolesByPolicy(cCtx.Context, cCtx.Args().Get(0), namespace, token)
					if err != nil {
						fmt.Println(textErr.Margin(0).Render("Error: ", err.Error()))
						return nil
					}
					return nil
				},
			},
			// Get Poilices that allow a path and op
			{
				Name:    "search-policy",
				Aliases: []string{"sp"},
				Usage:   "fetches auth roles that have a policy",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "namespace",
						Aliases:     []string{"ns"},
						Destination: &namespace,
						Usage:       "namespace of the path",
						Required:    true,
					},
					&cli.StringFlag{
						Name:        "path",
						Aliases:     []string{"p"},
						Value:       "",
						Destination: &vaultPath,
						Usage:       "vault path that is being accessed, e.g. secret/data/my/secret (DO NOT include namespace in the path)",
						Required:    true,
					},
					&cli.StringFlag{
						Name:        "operation",
						Aliases:     []string{"o"},
						Value:       "",
						Destination: &vaultOperation,
						Usage:       "Vault operation, e.g. create",
						Required:    true,
					},
				},
				Action: func(cCtx *cli.Context) error {
					_, token, err := getTokenDetails(accessor)
					if err != nil {
						fmt.Println(textErr.Margin(0).Render("Error: ", err.Error()))
						return nil
					}

					err = validateVaultOp(strings.ToLower(vaultOperation))
					if err != nil {
						fmt.Println(textErr.Margin(0).Render("Error: ", err.Error()))
						return nil
					}
					strings.ToLower(vaultOperation)
					_ = searchPolicies(cCtx.Context, vaultPath, strings.ToLower(vaultOperation), namespace, token, true)
					return nil
				},
			},
		},
		Action: func(cCtx *cli.Context) error {
			pipeErr := checkIfDataPipedIn()
			if pipeErr != nil {
				cli.ShowAppHelp(cCtx)
				return nil
			}

			paths, err := parsePathFromStdIn()
			if err != nil {
				fmt.Println(err.Error())
				fmt.Println(textErr.Margin(0).Render("Error: Unable to parse logs from stdin/stderr, usage: vault kv read foo/bar 2>&1 | " + os.Args[0]))
				return nil
			}

			fmt.Printf("\n\nDetected %d paths from stdin\n", len(paths))
			fmt.Println(textInfo.Margin(0).Render("Type the following into your command line to analyze:"))
			for _, path := range paths {
				cmd := os.Args[0]
				fmt.Println(textCmd.Render(fmt.Sprintf("%s analyze -p \"%s\" -o \"%s\" -ns \"%s\"", cmd, path.Path, path.Op, path.Namespace)))
			}
			return nil
		},
	}

	app.Suggest = true

	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
		app.Command(app.HelpName).Run(cli.NewContext(app, nil, nil))
	}
}

func getCustomPolicies() (*models.RequestRawPolicy, error) {
	rp := models.RequestRawPolicy{}
	if customPolicyFile != "" {
		if customPolicyNamespace == "" {
			return &rp, errors.New("no namespace provided for custom policy")
		}
		b, err := os.ReadFile(customPolicyFile) // just pass the file name
		if err != nil {
			return nil, errors.Wrap(err, "Error reading custom policy file")
		}
		policy := string(b)
		rp.Policy = &policy
		fp := strings.Split(customPolicyFile, "/")
		fn := fp[len(fp)-1]
		rp.Name = &fn
		rp.Namespace = &customPolicyNamespace
		return &rp, nil
	} else {
		return nil, nil
	}

}

func checkIfDataPipedIn() error {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeNamedPipe == 0 {
		return errors.New("no data piped in")
	} else {
		return nil
	}
}

func parsePathFromStdIn() ([]models.RequestPathDetails, error) {
	stdInText := ""
	paths := []models.RequestPathDetails{}
	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {
		fmt.Println(s.Text())
		stdInText += "\n" + s.Text()
	}
	if e := s.Err(); e != nil {
		return paths, e
	} else {
		var err error
		paths, err = parseVaultPathFromText(stdInText)
		if err != nil {
			return []models.RequestPathDetails{}, errors.Wrap(err, "error parsing parsing vault paths")
		}
		if len(paths) == 0 {
			return []models.RequestPathDetails{}, errors.New("No Vault errors in stdin")
		}
	}
	return paths, nil
}

func getTokenDetails(accessor string) (*models.RequestTokenDetails, string, error) {
	tokenDetails := models.RequestTokenDetails{}
	fmt.Println("Checking vault token")

	// Collect Vault EnvVars variables
	vaultAddr, vaultNs, vaultToken := common.CollectVaultEnvs()
	if vaultAddr == "" {
		return &tokenDetails, vaultToken, errors.New("VAULT_ADDR env var is empty, please set the env variable")
	}
	if vaultNs == "" {
		fmt.Println(textWarn.MarginTop(0).MarginLeft(2).Render(
			"* Warning: VAULT_NAMESPACE env var is empty, check if it's meant to be empty"))
	}
	if !noTokenHelper { // we want to explicitly use token in env var
		if common.CommandExists(common.VaultTokenHelperCmd) {
			fmt.Println(textWarn.MarginTop(0).MarginLeft(2).Render(
				"* Warning: Using vault-token-helper for token (not using env var, use `--no-th` to disable token-heper)"))
			var err error
			vaultToken, err = common.GetUserToken(vaultAddr, vaultNs)
			if err != nil {
				return &tokenDetails, vaultToken, errors.Wrap(err, "Error using vault-token-helper")
			}
		}
	}
	if vaultToken == "" {
		return &tokenDetails, vaultToken, errors.New("No vault token provided, be sure to set VAULT_TOKEN. If using vault-token-helper, make sure it is configured correctly")
	}

	PrintVaultVars(vaultAddr, vaultNs, vaultToken, !noTokenHelper)

	vh, err := vault_helper.NewVaultHelper(vaultAddr, vaultNs, vaultToken)
	if err != nil {
		return &tokenDetails, vaultToken, errors.Wrap(err, "error creating vault helper")
	}

	// Do a token self lookup to get all metadata
	data, err := vh.TokenLookupSelf()
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			fmt.Println(err.Error())
			return &tokenDetails, vaultToken, errors.New("Error: Your token might have expired, please renew your token and try again.")
		}
		return &tokenDetails, vaultToken, errors.Wrap(err, "Error doing token self lookup")
	}

	// Check if we should look up an accessor
	if accessor != "" {
		fmt.Println("Looking up accessor " + accessor)
		data, err = vh.TokenLookupAccessor(accessor)
		if err != nil {
			if strings.Contains(err.Error(), "permission denied") {
				fmt.Println(err.Error())
				return &tokenDetails, vaultToken, errors.New("Error: Your token does not have enough permissions to lookup an accessor")
			}
			return &tokenDetails, vaultToken, errors.Wrap(err, "error doing token lookup accessor")
		}
	}

	if !noTokenPolicies {
		// extract details from the token
		identityPolicies := []string{}
		policies := []string{}
		if data["identity_policies"] != nil {
			for _, ipo := range data["identity_policies"].([]interface{}) {
				identityPolicies = append(identityPolicies, ipo.(string))
			}
		}
		if data["policies"] != nil {
			for _, po := range data["policies"].([]interface{}) {
				policies = append(policies, po.(string))
			}
		}
		ep := map[string][]string{}
		if data["external_namespace_policies"] != nil {
			for nsId, po := range data["external_namespace_policies"].(map[string]interface{}) {
				for _, p := range po.([]interface{}) {
					ep[nsId] = append(ep[nsId], p.(string))
				}
			}
		}

		namespacePath := data["namespace_path"].(string)
		tokenDetails.NamespacePath = namespacePath
		tokenDetails.Policies = policies
		tokenDetails.ExternalNamespacePolicies = ep
		tokenDetails.IdentityPolicies = identityPolicies

		return &tokenDetails, vaultToken, nil
	} else {
		return nil, vaultToken, nil
	}

}

func getPolicyClient() pclient.ClientService {
	schemes := []string{"https"}
	if noTLS {
		schemes = []string{"http"}
	}
	transport := httptransport.New(serverUrl, "/", schemes)
	c := pclient.New(transport, nil)
	return c
}

func getGroupClient() gclient.ClientService {
	schemes := []string{"https"}
	if noTLS {
		schemes = []string{"http"}
	}
	transport := httptransport.New(serverUrl, "/", schemes)
	c := gclient.New(transport, nil)
	return c
}

func getAuthClient() aclient.ClientService {
	schemes := []string{"https"}
	if noTLS {
		schemes = []string{"http"}
	}
	transport := httptransport.New(serverUrl, "/", schemes)
	c := aclient.New(transport, nil)
	return c
}

func getAuth(vaultToken string) runtime.ClientAuthInfoWriter {
	return httptransport.APIKeyAuth("X-VAULT-TOKEN", "header", vaultToken)
}

func getPolicy(ctx context.Context, policyName string, namespace string, vaultToken string) *pclient.GetPolicyByNameOK {
	fmt.Printf("Fetching policy: %s in [%s]\n\n", textNote.Render(policyName), textNamespace.Render(namespace))
	pClient := getPolicyClient()
	req := pclient.NewGetPolicyByNameParamsWithContext(ctx)
	req.SetPolicyName(policyName)
	req.SetNamespace(&namespace)
	resp, err := pClient.GetPolicyByName(req, getAuth(vaultToken))
	if err != nil {
		handleRequestErrorAndDie(err)
		return nil
	}
	printServerMessages(resp.Payload.Messages)
	fmt.Printf("%s:\n", tMapKeyU.MarginLeft(4).Render(resp.Payload.PolicyName))
	fmt.Printf("%s\n\n", policyCodeStyle.Render(resp.Payload.PolicyRaw))
	return resp
}

func searchGroupsByPolicy(ctx context.Context, policyName string, namespace string, vaultToken string) *gclient.SearchGroupWithPolicyOK {
	fmt.Printf("\nFetching Groups that have policy: %s in [%s]\n\n",
		textNote.Render(policyName), textNamespace.Render(namespace))
	gClient := getGroupClient()
	req := gclient.NewSearchGroupWithPolicyParamsWithContext(ctx)
	req.SetPolicyName(policyName)
	req.SetNamespace(namespace)
	resp, err := gClient.SearchGroupWithPolicy(req, getAuth(vaultToken))
	if err != nil {
		handleRequestErrorAndDie(err)
		return nil
	}
	printServerMessages(resp.Payload.Messages)
	if len(resp.Payload.Groups) == 0 {
		fmt.Println(textErr.Margin(0).Render("No groups have that policy"))
		return nil
	}

	fmt.Printf("Groups that have policy %s [%v]:\n", textInfo.Render(policyName), textNamespace.Render(namespace))
	index := 0
	for _, g := range resp.Payload.Groups {
		index++
		a, _ := json.Marshal(g)
		group := vault_helper.Group{}
		json.Unmarshal(a, &group)
		renderGroup(&group, index, 4, "")

		if len(group.MemberGroupIds) > 0 {
			for i, childGroupId := range group.MemberGroupIds {
				mgRaw, ok := resp.Payload.AdditionalGroups[childGroupId]
				if !ok {
					continue
				}
				a, _ := json.Marshal(mgRaw)
				mg := vault_helper.Group{}
				json.Unmarshal(a, &mg)
				renderGroup(&mg, i+1, 8, "child group, inherits policy")
			}
		}
	}
	return resp
}

func renderGroup(group *vault_helper.Group, index int, indent int, annotation string) {
	output := ""
	output += fmt.Sprintf("%s %s",
		textIndex.MarginLeft(indent).Render(fmt.Sprintf("[%d]", index)),
		tMapKey.MarginLeft(0).Render(group.Name))
	if len(group.Alias.Name) > 0 {
		output += fmt.Sprintf(" [Alias: %s]", textInfo.Render(group.Alias.Name))
	}
	if len(annotation) > 0 {
		output += fmt.Sprintf(" (%s)", annotation)
	}
	fmt.Println(output)
}

func searchAuthRolesByPolicy(ctx context.Context, policyName string, namespace string, vaultToken string) *aclient.SearchAuthWithPolicyOK {
	fmt.Printf("Fetching auth roles that have policy: %s in [%s]\n\n",
		textNote.Render(policyName), textNamespace.Render(namespace))
	aClient := getAuthClient()
	req := aclient.NewSearchAuthWithPolicyParamsWithContext(ctx)
	req.SetPolicyName(policyName)
	req.SetNamespace(namespace)
	resp, err := aClient.SearchAuthWithPolicy(req, getAuth(vaultToken))
	if err != nil {
		handleRequestErrorAndDie(err)
		return nil
	}
	printServerMessages(resp.Payload.Messages)
	if len(resp.Payload.AuthRoles) == 0 {
		fmt.Println(textErr.Margin(0).Render("No auth roles have that policy"))
		return nil
	}

	fmt.Println("Auth roles:")
	for authType, roles := range resp.Payload.AuthRoles {
		fmt.Printf("%s [%s]:\n", tMapKeyU.MarginLeft(4).Render(authType), textNamespace.Render(namespace))
		for i, r := range roles {
			a, _ := json.Marshal(r)
			role := data_cache.AuthMountRole{}
			json.Unmarshal(a, &role)
			fmt.Printf("%s\n%s %s\n%s %s\n\n",
				textIndex.MarginLeft(4).Render(fmt.Sprintf("[%d]", i)),
				tMapKey2.MarginLeft(6).Render("Role Name:"),
				role.Role,
				tMapKey2.MarginLeft(6).Render("Mount Path"),
				role.MountPath)
		}
	}

	return resp
}

// PrintVaultVars
func searchPolicies(ctx context.Context, path string, op string, namespace string, vaultToken string, display bool) *pclient.SearchPolicyOK {
	fmt.Printf("Searching policies for: %s {%s} [%s] \n\n", textNote.Render(path), textNote.Render(op),
		textNamespace.Render(namespace))
	pClient := getPolicyClient()
	req := pclient.NewSearchPolicyParamsWithContext(ctx)
	req.Body.PathDetails = &pclient.SearchPolicyParamsBodyPathDetails{
		Namespace: namespace,
		Op:        op,
		Path:      path,
	}
	resp, err := pClient.SearchPolicy(req, getAuth(vaultToken))
	if err != nil {
		handleRequestErrorAndDie(err)
		return nil
	}
	printServerMessages(resp.Payload.Messages)
	if len(resp.Payload.GrantingPolicySegments) == 0 && len(resp.Payload.DenyingPolicySegments) == 0 {
		fmt.Println(textErr.Margin(0).Render("Error: Search returned no policies"))
		return nil
	}

	if display {
		if len(resp.Payload.GrantingPolicySegments) > 0 {
			fmt.Println(textSuccess.Render("Policies that ALLOW access:"))
			for ns, policy := range resp.Payload.GrantingPolicySegments {
				if len(policy) <= 0 {
					continue
				}
				for policyName, p := range policy {
					fmt.Printf("%s [%s]:\n%s\n",
						tMapKeyU.MarginLeft(6).Render(policyName),
						textNamespace.Render(ns),
						textLightGray.MarginLeft(7).Render("Policy segments allowing the operation:"))
					for _, policySegment := range p {
						fmt.Printf("%s\n\n", policyCodeStyleSmall.Render("...\n"+policySegment.Raw+"\n..."))
					}
				}
			}
		}
		if len(resp.Payload.DenyingPolicySegments) > 0 {
			fmt.Println(textFailure.Render("Policies that may DENY access:"))
			for ns, policy := range resp.Payload.DenyingPolicySegments {
				if len(policy) <= 0 {
					continue
				}
				for policyName, p := range policy {
					fmt.Printf("%s [%s]:\n%s\n",
						tMapKeyU.MarginLeft(6).Render(policyName),
						textNamespace.Render(ns),
						textLightGray.MarginLeft(7).Render("Policy segments denying the operation:"))
					for _, policySegment := range p {
						fmt.Printf("%s\n\n", policyCodeStyleSmall.Render("...\n"+policySegment.Raw+"\n..."))
					}
				}
			}
		}
	}

	return resp
}

func checkAllowed(ctx context.Context, path string, op string, namespace string, rawPolicy *models.RequestRawPolicy,
	explicitPolicies map[string][]string, vaultToken string, tokenDetails *models.RequestTokenDetails) *pclient.QueryPolicyAllowedOK {

	pClient := getPolicyClient()
	req := pclient.NewQueryPolicyAllowedParamsWithContext(ctx)
	req.Body = &models.Request{}
	req.Body.PathDetails = &models.RequestPathDetails{
		Namespace: namespace,
		Op:        op,
		Path:      path,
	}
	req.Body.TokenDetails = tokenDetails
	req.Body.RawPolicy = rawPolicy
	req.Body.Policies = explicitPolicies

	PrintRequestPolicies(req.Body)
	fmt.Printf("Checking if allowed: %s {%s} [%s]\n\n", textNote.Render(path), textNote.Render(op), textNamespace.Render(namespace))

	PrintTips(path, op)

	resp, err := pClient.QueryPolicyAllowed(req, getAuth(vaultToken))
	if err != nil {
		handleRequestErrorAndDie(err)
		return nil
	}
	printServerMessages(resp.Payload.Messages)
	if *resp.Payload.Allowed {
		fmt.Println(textSuccess.Render(fmt.Sprintf("'%s' on path '%s' is permitted.", op, path)))
		fmt.Printf("Allowed Capabilities: %s\n\n", textNote.Render(fmt.Sprintf("%v", resp.Payload.AllowedCap)))
		fmt.Println("Policy segments ALLOWING the operation:")
		index := 0
		for ns, policySegments := range resp.Payload.GrantingPolicySegments {
			for policyName, segmentList := range policySegments {
				fmt.Printf("%s\n%s (%s)\n", textIndex.MarginLeft(4).Render(fmt.Sprintf("[%d]", index)),
					tMapKey2.MarginLeft(6).Render(policyName),
					textNamespace.Render(ns))
				for _, segment := range segmentList {
					fmt.Printf("%s\n\n",
						policyCodeStyleSmall.Render("...\n"+segment.Raw+"\n..."))
				}

			}
		}
	} else {
		fmt.Println(textFailure.Render(fmt.Sprintf("'%s' on path '%s' is NOT permitted.", op, path)))
		if len(resp.Payload.DenyingPolicySegments) > 0 {
			fmt.Println("Policy segments DENYING the operation:")
			index := 0
			for ns, policySegments := range resp.Payload.DenyingPolicySegments {
				for policyName, segmentList := range policySegments {
					fmt.Printf("%s\n%s (%s)\n", textIndex.MarginLeft(4).Render(fmt.Sprintf("[%d]", index)),
						tMapKey2.MarginLeft(6).Render(policyName),
						textNamespace.Render(ns))
					for _, segment := range segmentList {
						fmt.Printf("%s\n\n",
							policyCodeStyleSmall.Render("...\n"+segment.Raw+"\n..."))
					}
				}
			}
		} else {
			fmt.Println(textNote.Margin(0).Render("No policies are explicitly denying the operation, " +
				"which means there are no policies allowing the operation, use `search-policy` cmd to see what policies might"))
		}
	}
	return resp
}

func tree(ctx context.Context, prefix string, rawPolicy *models.RequestRawPolicy, explicitPolicies map[string][]string,
	vaultToken string, tokenDetails *models.RequestTokenDetails) {
	pClient := getPolicyClient()
	req := pclient.NewPolicyTreeParamsWithContext(ctx)
	req.Body = &models.Request{}
	req.Body.RawPolicy = rawPolicy
	req.Body.Policies = explicitPolicies
	req.Body.TokenDetails = tokenDetails
	req.Body.PathDetails = nil

	PrintRequestPolicies(req.Body)
	fmt.Println("Generating tree\n")
	resp, err := pClient.PolicyTree(req, getAuth(vaultToken))
	if err != nil {
		handleRequestErrorAndDie(err)
		return
	}
	printServerMessages(resp.Payload.Messages)
	a, _ := json.Marshal(resp.Payload.Tree)
	tr := trie.Tree{}
	json.Unmarshal(a, &tr)

	tr.Viz(prefix,
		func(s string) string { // leaf rendering
			if s == "" {
				return s
			}
			if strings.Contains(s, "deny") {
				return textFailure.Render(s)
			} else {
				return textLightGray.Render(s)
			}
		},
		func(s string) string { // path rendering
			if s == "" {
				return s
			}
			return textInfo.Render(s)
		})
	return

}

func analyze(ctx context.Context, path string, op string, pathNamespace string, explicitPolicies map[string][]string, vaultToken string, tokenDetails *models.RequestTokenDetails) {
	scan := bufio.NewScanner(os.Stdin)
	allowedResp := checkAllowed(ctx, path, op, pathNamespace, nil, explicitPolicies, vaultToken, tokenDetails)
	if *allowedResp.Payload.Allowed {
		return
	}

	fmt.Printf(textInput.Render("%s"), "Search for POLICIES that might give access? Press 'Enter' to search...")
	scan.Scan()
	fmt.Println()

	policyResp := searchPolicies(ctx, path, op, pathNamespace, vaultToken, false)
	if len(policyResp.Payload.GrantingPolicySegments) <= 0 { // no policies found
		return
	}

	// enumerate each policy
	policyChoices := []Policy{}
	selectedPolicy := Policy{}
	for ns, policySegments := range policyResp.Payload.GrantingPolicySegments {
		for policyName, _ := range policySegments {
			policyChoices = append(policyChoices, Policy{
				Name:      policyName,
				Namespace: ns,
			})
		}
	}
	_policySelectorTitle = "Following policies give access. Select a policy to search for GROUPS: (Ctrl+C to exit)"
	if len(policyChoices) == 1 { // if only one policy then no need to ask
		selectedPolicy = policyChoices[0]
	} else { // if more than one then ask user which policy to search for
		_policySelectorChoices = policyChoices
		p := tea.NewProgram(model{})
		m, err := p.Run()
		if err != nil {
			fmt.Println("error creating policySelector:", err)
			os.Exit(1)
		}

		// Assert the final tea.Model to our local model and print the choice.
		if m, ok := m.(model); ok && m.choice.Name != "" {
			selectedPolicy = m.choice
		}
	}

	_ = searchGroupsByPolicy(ctx, selectedPolicy.Name, selectedPolicy.Namespace, vaultToken)

	fmt.Printf(textInput.Render("Search for OIDC/APPROLES that might have the policy '" +
		selectedPolicy.Name + "?' Press 'Enter' to search..."))
	scan.Scan()
	fmt.Println()
	_ = searchAuthRolesByPolicy(ctx, selectedPolicy.Name, selectedPolicy.Namespace, vaultToken)
}

func printServerMessages(msgs []*models.Message) {
	if len(msgs) <= 0 {
		return
	}
	fmt.Println("Messages from server:")
	for _, msg := range msgs {
		switch msg.MsgType {
		case models.MessageMsgTypeWarn:
			fmt.Println(textWarn.MarginTop(1).MarginLeft(4).Render("* Warning: " + msg.MsgBody))
		case models.MessageMsgTypeErr:
			fmt.Println(textErr.MarginTop(1).MarginLeft(4).Render("** Error: " + msg.MsgBody))
		default:
			fmt.Println(textNote.MarginTop(1).MarginLeft(4).Render("Info: " + msg.MsgBody))
		}
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Println("\n")
}

func handleRequestErrorAndDie(err error) {
	code := 0
	requestId := ""
	switch v := err.(type) {
	case *pclient.QueryPolicyAllowedBadRequest:
		code = v.Code()
		requestId = v.Payload.ID
		printServerMessages(v.Payload.Messages)
	case *pclient.QueryPolicyAllowedInternalServerError:
		code = v.Code()
		requestId = v.Payload.ID
	case *pclient.QueryPolicyAllowedUnauthorized:
		code = v.Code()
		requestId = v.Payload.ID
	case *pclient.PolicyTreeBadRequest:
		code = v.Code()
		requestId = v.Payload.ID
		printServerMessages(v.Payload.Messages)
	case *pclient.PolicyTreeInternalServerError:
		code = v.Code()
		requestId = v.Payload.ID
	case *pclient.PolicyTreeUnauthorized:
		code = v.Code()
		requestId = v.Payload.ID
	case *pclient.GetPolicyByNameBadRequest:
		code = v.Code()
		requestId = v.Payload.ID
		printServerMessages(v.Payload.Messages)
	case *pclient.GetPolicyByNameInternalServerError:
		code = v.Code()
		requestId = v.Payload.ID
	case *pclient.GetPolicyByNameUnauthorized:
		code = v.Code()
		requestId = v.Payload.ID
	case *pclient.GetPolicyByNameNotFound:
		code = v.Code()
		requestId = v.Payload.ID
	case *pclient.SearchPolicyBadRequest:
		code = v.Code()
		requestId = v.Payload.ID
		printServerMessages(v.Payload.Messages)
	case *pclient.SearchPolicyInternalServerError:
		code = v.Code()
		requestId = v.Payload.ID
	case *pclient.SearchPolicyUnauthorized:
		code = v.Code()
		requestId = v.Payload.ID
	case *gclient.SearchGroupWithPolicyBadRequest:
		code = v.Code()
		requestId = v.Payload.ID
		printServerMessages(v.Payload.Messages)
	case *gclient.SearchGroupWithPolicyInternalServerError:
		code = v.Code()
		requestId = v.Payload.ID
	case *gclient.SearchGroupWithPolicyUnauthorized:
		code = v.Code()
		requestId = v.Payload.ID
	case *gclient.SearchGroupWithPolicyNotFound:
		code = v.Code()
		requestId = v.Payload.ID
	case *aclient.SearchAuthWithPolicyBadRequest:
		code = v.Code()
		requestId = v.Payload.ID
		printServerMessages(v.Payload.Messages)
	case *aclient.SearchAuthWithPolicyInternalServerError:
		code = v.Code()
		requestId = v.Payload.ID
	case *aclient.SearchAuthWithPolicyUnauthorized:
		code = v.Code()
		requestId = v.Payload.ID
	case *aclient.SearchAuthWithPolicyNotFound:
		code = v.Code()
		requestId = v.Payload.ID
	default:
		fmt.Println(textErr.Render(fmt.Sprintf("%v", err)))
		os.Exit(0)
	}

	fmt.Println(textErr.Margin(0).Render("\nError from server:"))
	errorMessage := http.StatusText(code)
	fmt.Printf("Code: %s %s\nRequest Id: %s\n",
		textErr.Margin(0).Render(strconv.Itoa(code)), textErr.Render("("+errorMessage+")"),
		textLightGray.Render(requestId))
	os.Exit(0)
}

func parseVaultPathFromText(text string) ([]models.RequestPathDetails, error) {
	rps := []models.RequestPathDetails{}
	logrus.Debugln("parsing vault paths from text")

	// Compile the regex for Vault errors
	r, err := regexp.Compile("((Namespace: ([\\S]+)\\n)?)URL: (GET|POST|LIST|PUT|DELETE) https?:\\/\\/((www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_\\+.~#?&//=]*))\\nCode: ([0-9][0-9][0-9])")
	if err != nil {
		return rps, errors.Wrap(err, "error compiling regex for path parsing")
	}
	s := r.FindAllString(text, -1)
	logrus.Debug("total vault paths ", len(s))
	for i, a := range s {
		log.Printf("Parsing [%d/%d]\n%s", i+1, len(s), a)
		httpMethod := ""
		urlPath := ""
		namespace := ""
		code := 0
		if strings.HasPrefix(a, "Namespace") {
			_, err = fmt.Sscanf(a, "Namespace: %s\nURL: %s %s\nCode: %d", &namespace, &httpMethod, &urlPath, &code)
		} else {
			_, err = fmt.Sscanf(a, "URL: %s %s\nCode: %d", &httpMethod, &urlPath, &code)
		}
		if err != nil {
			return rps, errors.Wrap(err, "error parsing path from regex results, string: "+a)
		}

		u, err := url.Parse(urlPath)
		if err != nil {
			return rps, errors.Wrap(err, "error parsing url: "+urlPath)
		}

		v, _ := url.ParseQuery(u.RawQuery)

		if v["list"] != nil && v["list"][0] == "true" {
			httpMethod = "LIST"
			logrus.Debug("list=true is set, using 'LIST' HTTP method")
		}

		vaultPath := strings.TrimPrefix(u.Path, "/v1/")
		vaultPath = strings.TrimSuffix(vaultPath, "?list=true")

		op, err := httpMethodToVaultCapability(httpMethod)
		if err != nil {
			return rps, errors.Wrap(err, "error converting http method to a vault operation")
		}

		rps = append(rps, models.RequestPathDetails{
			Namespace: namespace,
			Op:        op,
			Path:      vaultPath,
		})
	}

	return rps, nil
}

func PrintTips(path string, op string) {
	tips := []string{}
	if op == vault.ListCapability {
		if strings.HasSuffix(path, "/") {
			tips = append(tips, "Try without the trailing `/`, LIST cmd can be ambiguous on trailing slash")
		} else {
			tips = append(tips, "Try adding a `/`at the end, LIST cmd can be ambiguous on trailing slash")
		}
	}
	if strings.HasPrefix(path, "sys/internal/ui/mount") {
		tips = append(tips, "'sys/internal/ui/mount' errors usually mean the path is wrong, "+
			"its trying to read on a mount that might not exist or have permissions to")
	}
	if len(tips) > 0 {
		fmt.Println(textNote.Margin(0).Render("=== TIPS/WARNINGS ==="))
		for i, tip := range tips {
			fmt.Println(textWarn.MarginTop(1).MarginLeft(2).Render(fmt.Sprintf("* [%d]: %s\n", i+1, tip)))
		}
	}
}

func PrintVaultVars(addr, ns, token string, tokenHelper bool) {
	tokenHelperText := ""
	if tokenHelper {
		tokenHelperText = " (Using Token Helper)"
	}
	keyFormatting := tMapKey.MarginLeft(4)
	fmt.Println(textNote.Render("Vault vars:"))
	fmt.Printf("%s: %s\n%s: %s\n%s: %s\n\n",
		keyFormatting.Render("VAULT_ADDR:"),
		addr,
		keyFormatting.Render("VAULT_NAMESPACE:"),
		textNamespace.Render(ns),
		keyFormatting.Render("VAULT_TOKEN (last 3 char):"),
		fmt.Sprintf("...%s%s", token[len(token)-3:], textLightGray.Render(tokenHelperText)))
}

func PrintRequestPolicies(req *models.Request) {
	keyFormatting := tMapKey.MarginLeft(4)
	if req.RawPolicy != nil {
		fmt.Println(textNote.Margin(0).Render("Custom policy:"))
		fmt.Printf("%s: %s\n", keyFormatting.Render("Custom Policy file"), *req.RawPolicy.Name)
		fmt.Printf("%s: %s\n", keyFormatting.Render("Custom Policy namespace"), *req.RawPolicy.Namespace)
	}
	if len(req.Policies) > 0 {
		fmt.Println(textNote.Margin(0).Render("Policies:"))
		fmt.Printf("%s: %v\n", keyFormatting.Render("Policies (explicit)"), req.Policies)
	}
	if req.TokenDetails != nil {
		fmt.Println(textNote.Margin(0).Render("Token:"))
		if len(req.TokenDetails.Policies) > 0 {
			fmt.Printf("%s: %v\n", keyFormatting.Render("Policies"), req.TokenDetails.Policies)
		}
		if len(req.TokenDetails.ExternalNamespacePolicies) > 0 {
			fmt.Printf("%s: %v\n", keyFormatting.Render("External Namespace policies"), req.TokenDetails.ExternalNamespacePolicies)
		}
		if len(req.TokenDetails.IdentityPolicies) > 0 {
			fmt.Printf("%s: %v\n", keyFormatting.Render("Identity Policies"), req.TokenDetails.IdentityPolicies)
		}
		if req.TokenDetails.NamespacePath != "" {
			fmt.Printf("%s: %s\n", keyFormatting.Render("Token Namespace"), req.TokenDetails.NamespacePath)
		}
	}
	fmt.Println("---\n")
}

func httpMethodToVaultCapability(httpMethod string) (string, error) {
	// From: https://developer.hashicorp.com/vault/docs/concepts/policies#capabilities
	switch httpMethod {
	case "GET":
		return vault.ReadCapability, nil
	case "POST":
		return vault.CreateCapability, nil
	case "PUT":
		return vault.UpdateCapability, nil
	case "PATCH":
		return vault.PatchCapability, nil
	case "DELETE":
		return vault.DeleteCapability, nil
	case "LIST":
		return vault.ListCapability, nil
	default:
		return "", errors.New(fmt.Sprintf("unsupported http method %s", httpMethod))
	}
}

func validateVaultOp(op string) error {
	switch op {
	case vault.ListCapability:
	case vault.DenyCapability:
	case vault.CreateCapability:
	case vault.ReadCapability:
	case vault.UpdateCapability:
	case vault.DeleteCapability:
	case vault.SudoCapability:
	case vault.RootCapability:
	case vault.PatchCapability:
	default:
		return errors.New(fmt.Sprintf("Vault operation '%s' in invalid", op))
	}
	return nil
}
