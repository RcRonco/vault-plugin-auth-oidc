# Vault Plugin: OIDC Auth Backend

### Don't ready for production yet
This is a standalone backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This plugin allows for OpenID Connect, Code flow to authenticate with Vault.
This plugin build to allow true sso for Vault UI.

## Quick Links
    - Vault Website: https://www.vaultproject.io
    - Vault Project Github: https://www.github.com/hashicorp/vault

## Getting Started

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html)
and is meant to work with Vault. This guide assumes you have already installed Vault
and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with Vault](https://www.vaultproject.io/intro/getting-started/install.html).

To learn specifically about how plugins work, see documentation on [Vault plugins](https://www.vaultproject.io/docs/internals/plugins.html).

### Configuration

1. Install and register the plugin.

Put the plugin binary (`vault-plugin-auth-oidc`) into a location of your choice. This directory
will be specified as the [`plugin_directory`](https://www.vaultproject.io/docs/configuration/index.html#plugin_directory)
in the Vault config used to start the server.

```json
...
plugin_directory = "path/to/plugin/directory"
...
```

```sh
$ vault write sys/plugins/catalog/oidc-auth-plugin \   
  sha_256="$(shasum -a 256 'vault-plugin-auth-oidc' | cut -d ' ' -f1)" \
  command="vault-plugin-auth-oidc -client-cert server.crt -client-key server.key"
```

2. Enable the OpenID Connect auth method:

```sh
$ vault auth-enable -path=oidc -plugin-name=oidc-auth-plugin plugin
Successfully enabled 'kerberos' at 'oidc'!
```

3. Use the /config endpoint to configure OpenID Connect against Idp

```sh
vault write auth/oidc/config redirect_url="http://vault.rocks/sso/index.html" \  
                             client_id=XXXXXXXXXX secret_id=XXXXXXXXXXXXXX scopes="email,profile" \
                             oidc_discovery_url="https://xxxx.auth0.com/"
```

* With HTTP  
payload.json:
```json
{
    "client_id": "XXXXXXXXXXXXXXXX",
    "max_ttl": 0,
    "oidc_discovery_url": "https://xxxx.auth0.com/",
    "redirect_url": "http://vault.rocks/sso/index.html",
    "scopes": [
      "email",
      "profile",
      "openid"
    ],
    "secret_id": "XXXXXXXXXXXXXX"
}
```

```sh
curl -X PUT -H "X-Vault-Token: XXXXXXXXXXX" --data @payload.json http://vault.co/v1/auth/oidc/config
```

4. Configure /claims endpoint to map Claims data into user data.

```sh
vault write auth/oidc/claims all_metadata=false display_name_claim=nickname groups_claim=usr-groups \
      metadata_claims="username,email=address" policies_claim=usr-policies user_claim=email
```

* With HTTP  
payload.json:
```json
{
    "all_metadata": false,
    "display_name_claim": "nickname",
    "groups_claim": "usr-groups",
    "groups_delimiter": ",",
    "metadata_claims": [
      "username",
      "email=address"
    ],
    "policies_claim": "usr-policies",
    "policies_delimiter": ",",
    "user_claim": "email"
}
```

```sh
curl -X PUT -H "X-Vault-Token: XXXXXXXXXXX" --data @payload.json http://vault.co/v1/auth/oidc/claims
```
