package oidc

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathSecretID(b *openIDConnectAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: `secret-id$`,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathSecretIDRead,
		},

		HelpSynopsis:    secretIDHelpSyn,
		HelpDescription: secretIDHelpDesc,
	}
}

func (b *openIDConnectAuthBackend) pathSecretIDRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"client_id":             config.ClientID,
			"secret_id":             config.SecretID,
		},
	}

	return resp, nil
}

const (
	secretIDHelpSyn = `
Return OpenID Connect Client information.
`
	secretIDHelpDesc = `
Return OpenID Connect Relaying party client ID and secret ID.
Used to get secret id intentionaly instead of get the secret ID whenever the backend config is red.
`
)
