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

import (
	"fmt"
	"github.com/pkg/errors"
	"os"
	"os/exec"
)

const VaultTokenHelperCmd = "vault-token-helper"
const CacheReadyKey = "ReadyZ"

func CollectVaultEnvs() (addr string, ns string, token string) {
	addr = os.Getenv("VAULT_ADDR")
	ns = os.Getenv("VAULT_NAMESPACE")
	token = os.Getenv("VAULT_TOKEN")
	return
}

func CommandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func GetUserToken(vaultAddr string, vaultNamespace string) (string, error) {
	cmd := exec.Command(VaultTokenHelperCmd, "get")
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("VAULT_ADDR=%s", vaultAddr))
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("VAULT_NAMESPACE=%s", vaultNamespace))
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	if out != nil {
		return string(out), nil
	}
	err = errors.New("could not find user token")
	return "", err
}
