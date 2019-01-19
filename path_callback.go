package oidc

import (
	"context"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"golang.org/x/oauth2"
)

func pathCallback(b *openIDConnectAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: `callback$`,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:           b.pathCallback,
			logical.AliasLookaheadOperation: b.pathCallback,
		},

		HelpSynopsis:    pathCallbackSyn,
		HelpDescription: pathCallbackDesc,
	}
}

func (b *openIDConnectAuthBackend) pathCallback(ctx context.Context, req *logical.Request,
												d *framework.FieldData) (*logical.Response, error) {
	// Fetch Config and ClaimsConfig
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("could not load OIDC configuration"), nil
	}
	claimsConfig, err := b.claimsConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if claimsConfig == nil {
		return logical.ErrorResponse("could not load OIDC Mapping configuration"), nil
	}

	// Check for state nonce to mitigate CSRF
	{
		state, ok := b.stateCache.Get(req.Connection.RemoteAddr)
		if !ok && req.Data["state"] != nil {
			return logical.ErrorResponse("Could not find connection state, " +
											  "this request may be forged or took over 5 minutes"), nil
		}
		if state != req.Data["state"].(string) {
			return logical.ErrorResponse("state nonce not matching, this request may be forged"), nil
		}
	}

	// Create provider
	provider, err := b.getProvider(ctx, config)
	if err != nil {
		return nil, errwrap.Wrapf("error getting provider for login operation: {{err}}", err)
	}

	// Exchange code for JWT to get claims
	oauthConfig := config.config2OauthConfig(provider)
	oauth2Token, err := oauthConfig.Exchange(ctx, req.Data["code"].(string))
	if err != nil {
		return nil, errwrap.Wrapf("Failed to exchange token: {{err}}", err)
	}

	// Fetch user information JWT
	userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		return nil, errwrap.Wrapf("Failed to exchange token: {{err}}", err)
	}

	// Map user information from Idp to Vault user
	userData, err := claimsConfig.parseUserInfo(userInfo)
	if err != nil {
		return nil, errwrap.Wrapf("Failed to map user claims: {{err}}", err)
	}

	resp := &logical.Response{
		Auth: &logical.Auth{
			DisplayName: userData.DisplayName,
			Policies: userData.Policies,
			Metadata: userData.Metadata,
			Alias: &logical.Alias{
				Name: userData.Username,
			},
			LeaseOptions: logical.LeaseOptions{
				TTL:       config.TTL,
				MaxTTL:    config.MaxTTL,
				Renewable: true,
			},
		},
	}

	// Map groups
	for _, grp := range userData.Groups {
		resp.Auth.GroupAliases = append(resp.Auth.GroupAliases, &logical.Alias{Name: grp})
	}

	return resp, nil
}

const (
	pathCallbackSyn = `
	Log in with a OpenID Connect.
	`

	pathCallbackDesc = `
	This endpoint authenticates using Auth0 with OpenID Connect. Please be sure to
	read the note on escaping from the path-help for the 'config' endpoint.
	`
)