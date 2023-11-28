# vault-query

A tool to query [Vault](https://www.vaultproject.io/) groups, policies, roles and shed more light on why a request is allowed or disallowed. 

When accessing an unathorized path, Vault returns `403 permission denied` error with no further details; while this makes sense from a security point of view, it does leave administrators puzzled when trying to diagnose policy issues. Thats where this tool comes to the rescue! It can analyse all the policies, groups, roles and identify why a token is allowed/disallowed on a path.

Under the hood, vault-query periodically fetches all policies, group, roles in all namespaces. It pre-renders the ACL for each policy, and on request returns back the outcome of the ACL along with more details on the allowing policy (or disallowing policy). It uses the same objects and code as Vault to render the ACL and evaluate requests.

### Components

#### Vault-query server

The server queries Vault and maintains a pre-rendered list of policies, groups and roles. The data is kept in memory. It exposes the redered data through an API, which can be used by clients to query. The API was built using [go-swagger](https://github.com/go-swagger/go-swagger). The API requires a valid vault token as a way to authenicate.

#### Vault-query CLI

The CLI is just a consumer for the vault-query API. It does RestAPI requests to the server, and reders the results in a fancy way. It can also identify common vault issues and return errors/tips before doing a query to the server

### Supported features

These are the list of features of Vault that is supported:

  - Querying policies based on path and operation
    - HCL policies
    - Wildcard policies
    - Cross-namespace policies
  - Querying Groups and OIDC/Approle/... roles for a specific policy
  - Searching for policies that MIGHT give access on a path
  - Tree visualisation from policies
  - Uploading custom policy (HCL) for evaluation
  - [Vault-token-helper](https://github.com/joemiller/vault-token-helper) integration
  - Swagger API

### Limitations

There are some limitations to this tool and what it can provide:

  - Tempalted policies are not supported (they wont be rendered)
  - Sentinel policies are not supported
  - The policies are updated periodically, so the evaluation is only as fresh as the last fetch time. (something that needs further investigation, maybe a more sophiscated cache)
  - All cache is maintained in memory (policies, groups, roles), which has sufficed for even large use cases, however it is a limitation that may need to be addressed in the future in case of larger amounts of data.
  - Currently the API only checks for a valid vault token (further RBAC is not supported at the moment).

## Examples

### Analyze vault permission issues

#### Example

 - `vq analyze -p secret/data/foo/bar -o create -ns foons`
 - `vq analyze --accessor abc123 -p secret/data/foo/bar -o create -ns foons`

This will start a interactive session and check for permission issues 

### Check if a request is allowed

#### Example

`> vq check-allowed -p secret/data/prod/infra/test/a -o read -ns foons/prod`

```
...
Checking if allowed: secret/data/prod/infra/test/a {read} [foons/prod]

'read' on path 'secret/data/prod/infra/test/a' is NOT permitted.
Policy segments DENYING the operation:
    [0]
      abc-prod-secrets-apps (foons/)
...
```

Also supports using `--accessor`

### Search for policies that may allow (or deny) a path

#### Example
`> vq search-policy -ns foons/prod -p secret/data/prod/k8s/+/admin -o read`

```
Searching policies for: secret/data/prod/k8s/+/admin {read} [foons/prod]

Policies that ALLOW access:
      vault_admin [foons/]:
       Policy segments allowing the operation:
            ...
            path "*" {
            	capabilities=["create","read","update","delete","list","sudo"]
            }
            ...

      abc-prod-secrets-apps [foons/]:
       Policy segments allowing the operation:
            ...
            path "prod/secret/*" {
            	capabilities=["create","read","update","delete","list"]
            }
            ...

      devops_admin [foons/prod/]:
       Policy segments allowing the operation:
            ...
            path "secret/*" {
            	capabilities=["create","read","update","delete","list"]
            }
            ...

```


### Search for groups and auth roles that have a policy 

#### Example for searching groups

`> vq search-groups-by-policy -ns foons abc-prod-secrets-apps`

```
...
Fetching Groups that have policy: abc-prod-secrets-apps in [foons]

Groups that have policy abc-prod-secrets-apps [foons]:
    [1] cnp-abc-prod-deployer
        [1] abc-vault-prod-deployer [Alias: CN=abc-vault-prod-deployer] (child group, inherits policy)
...
```

#### Example for searching auth roles and approles

`> vq search-auth-by-policy -ns foons vault_admin`
```
...
Fetching auth roles that have policy: vault_admin in [foons]

Auth roles:
    oidc [foons]:
    [0]
      Role Name: vault_admin
      Mount Path oidc/
```

### Test custom policies

#### Example

`custom_policy.hcl`
```
path "secretTest/data/custom/policy/test/foo" {
    capabilities=["read","list"]
}
```

`vq check-allowed -p secretTest/data/custom/policy/test/foo -o read -ns foons --custom-policy-file custom_policy.hcl --custom-policy-namespace foons`
```
...
Checking if allowed: secretTest/data/custom/policy/test/foo {read} [foons]

'read' on path 'secretTest/data/custom/policy/test/foo' is permitted.
Allowed Capabilities: [read list]

Policy segments ALLOWING the operation:
    [0]
      custom_policy.hcl (foons/)
...
```

### Create a Tree from the policies

#### Example

`vq tree --prefix=foons/prod/k8s/`

```
...

Generating tree

├─k8s/
|    ├─+/
|    |    ├─roles* [read list]
|    |    ├─issue/* [read list update]
|    |    ├─issuer/+/issue/* [create update]
|    ├─a/b/c/issue/
|    |    ├─devops [create update]
|    |    ├─k8s-admi* [deny]
|    |    ├─k8s-admin [create update]
|    ├─prod/* [deny]
```


## Building/Compiling

Pre-requisites:
 - Golang 1.19+
 - goswagger (https://goswagger.io/)
 - Make


#### Server

 - Building the server: `make build-server`
 - Building docker image: `make image`
 - Generating Swagger code: `make swagger`

#### Client/CLI

 - Building the cli: `make build-client`

## Contributing

Please refer to [CONTRIBUTING.md](./CONTRIBUTING.md)

## License

Please refer to [LICENSE](./LICENSE)
