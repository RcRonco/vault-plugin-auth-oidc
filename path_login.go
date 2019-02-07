package oidc

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/fatih/structs"
	"github.com/hashicorp/vault/plugins/helper/database/credsutil"
	"github.com/patrickmn/go-cache"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathLogin(b *openIDConnectAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: `login$`,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:           b.pathLogin,
			logical.AliasLookaheadOperation: b.pathLoginAliasLookahead,
		},
		HelpSynopsis:    pathLoginSyn,
		HelpDescription: pathLoginDesc,
	}
}

func (b *openIDConnectAuthBackend) pathLoginAliasLookahead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := d.Get("username").(string)
	if username == "" {
		return nil, fmt.Errorf("missing username")
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Alias: &logical.Alias{
				Name: username,
			},
		},
	}, nil
}

func (b *openIDConnectAuthBackend) pathLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("could not load OIDC configuration"), nil
	}

	provider, err := b.getProvider(ctx, config)
	if err != nil {
		return nil, errwrap.Wrapf("error getting provider for login operation: {{err}}", err)
	}

	// Generate nonce
	nonce, err := credsutil.RandomAlphaNumeric(16, true)
	if err != nil {
		return nil, errwrap.Wrapf("error to generate state nonce: {{err}}", err)
	}

	// Set nonce as state parameter in cache with Remote address to check for CSRF attempts
	b.stateCache.Set(req.Connection.RemoteAddr, nonce, cache.DefaultExpiration)
	oauthConfig := config.config2OauthConfig(provider)

	resp := &logical.Response{
		Redirect: oauthConfig.AuthCodeURL(stateLogin, oidc.Nonce(nonce)),
		Data: structs.New(oauthConfig).Map(),
	}

	return resp, nil
}

const (
	pathLoginSyn = `
	Log in with a OpenID Connect.
	`

 	pathLoginDesc = `
	This endpoint authenticates using Auth0 with OpenID Connect. Please be sure to
	read the note on escaping from the path-help for the 'config' endpoint.
	`

 	stateLogin = "Vault-Login"
)