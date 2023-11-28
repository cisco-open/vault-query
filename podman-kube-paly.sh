# Copyright 2023 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

rendered_filename=$1-rendered.yaml
addr=$(echo $VAULT_ADDR | base64)
ns=$(echo $VAULT_NAMESPACE | base64)
token=$(echo $VAULT_TOKEN | base64)
sed "s|%VAULT_ADDR|$addr|g;s|%VAULT_NAMESPACE|$ns|g;s|%VAULT_TOKEN|$token|g" $1  > $rendered_filename
cat $rendered_filename | podman kube play --replace -
