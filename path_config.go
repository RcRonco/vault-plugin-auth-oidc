package oidc

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	"context"

	oidc "github.com/coreos/go-oidc"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"golang.org/x/oauth2"
)

func pathConfig(b *openIDConnectAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: `config`,
		Fields: map[string]*framework.FieldSchema{
			"client_id": {
				Type:        framework.TypeString,
				Description: `OpenID Connect Relaying Party Client ID.`,
			},
			"secret_id": {
				Type:        framework.TypeString,
				Description: `<Required> OpenID Connect Relaying Party Secret ID.`,
			},
			"oidc_discovery_url": {
				Type:        framework.TypeString,
				Description: `<Required> OIDC Discovery URL, without any .well-known component (base path).`,
			},
			"redirect_url": {
				Type:        framework.TypeString,
				Description: `<Required> Audience claim that is valid for login.`,
			},
			"scopes": {
				Type:        framework.TypeCommaStringSlice,
				Description: "<Optional> Provided scopes.",
			},
			"oidc_discovery_ca_pem": {
				Type:        framework.TypeString,
				Description: "<Optional> The CA certificate or chain of certificates, in PEM format, to use to validate conections to the OIDC Discovery URL. If not set, system certificates are used.",
			},
			"ttl": {
				Type:        framework.TypeString,
				Description: `<Optional> Duration after which authentication will be expired`,
			},
			"max_ttl": {
				Type:        framework.TypeString,
				Description: `<Optional> Maximum duration after which authentication will be expired`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathConfigRead,
			logical.UpdateOperation: b.pathConfigWrite,
		},

		HelpSynopsis:    confHelpSyn,
		HelpDescription: confHelpDesc,
	}
}

func (b *openIDConnectAuthBackend) config(ctx context.Context, s logical.Storage) (*oidcConfig, error) {
	b.l.RLock()
	defer b.l.RUnlock()

	if b.cachedConfig != nil {
		return b.cachedConfig, nil
	}

	entry, err := s.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	result := &oidcConfig{}
	if entry != nil {
		if err := entry.DecodeJSON(result); err != nil {
			return nil, err
		}
	}

	b.cachedConfig = result

	return result, nil
}

func (b *openIDConnectAuthBackend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
			"secret_id":             "Use the secret ID endpoint to get the Secret ID",
			"oidc_discovery_url":    config.OIDCProviderURL,
			"redirect_url":          config.RedirectURL,
			"scopes":                config.Scopes,
			"oidc_discovery_ca_pem": config.OIDCDiscoveryCAPEM,
			"ttl":        config.TTL,
			"max_ttl":    config.MaxTTL,
		},
	}

	return resp, nil
}

func (b *openIDConnectAuthBackend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config := &oidcConfig{
		ClientID:           d.Get("client_id").(string),
		SecretID:           d.Get("secret_id").(string),
		OIDCProviderURL:    d.Get("oidc_discovery_url").(string),
		OIDCDiscoveryCAPEM: d.Get("oidc_discovery_ca_pem").(string),
		Scopes:             append(d.Get("scopes").([]string), oidc.ScopeOpenID),
	}

	// Run checks on values
	switch {
	case config.ClientID == "" || config.SecretID == "":
		return logical.ErrorResponse("client and secret id's must be set."), nil
	case len(config.Scopes) == 0:
		return logical.ErrorResponse("client and secret id's must be set."), nil
	case config.OIDCProviderURL != "":
		_, err := b.createProvider(config)
		if err != nil {
			return logical.ErrorResponse(errwrap.Wrapf("error checking discovery URL: {{err}}", err).Error()), nil
		}
	default:
		return logical.ErrorResponse("unknown condition"), nil
	}
	config.RedirectURL = d.Get("redirect_url").(string)
	if len(config.RedirectURL) == 0 {
		return logical.ErrorResponse("redirect_url must be set."), nil
	}
	//config.RedirectURL += "/v1/" + req.MountPoint + callbackPath

	var ttl time.Duration
	var err error
	ttlRaw, ok := d.GetOk("ttl")
	if !ok || len(ttlRaw.(string)) == 0 {
		ttl = 0
	} else {
		ttl, err = time.ParseDuration(ttlRaw.(string))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("Invalid 'ttl':%s", err)), nil
		}
	}

	var maxTTL time.Duration
	maxTTLRaw, ok := d.GetOk("max_ttl")
	if !ok || len(maxTTLRaw.(string)) == 0 {
		maxTTL = 0
	} else {
		maxTTL, err = time.ParseDuration(maxTTLRaw.(string))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("Invalid 'max_ttl':%s", err)), nil
		}
	}

	config.TTL = ttl
	config.MaxTTL = maxTTL

	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

func (b *openIDConnectAuthBackend) createProvider(config *oidcConfig) (*oidc.Provider, error) {
	var certPool *x509.CertPool
	if config.OIDCDiscoveryCAPEM != "" {
		certPool = x509.NewCertPool()
		if ok := certPool.AppendCertsFromPEM([]byte(config.OIDCDiscoveryCAPEM)); !ok {
			return nil, errors.New("could not parse 'oidc_discovery_ca_pem' value successfully")
		}
	}

	tr := cleanhttp.DefaultPooledTransport()
	if certPool != nil {
		tr.TLSClientConfig = &tls.Config{
			RootCAs: certPool,
		}
	}
	tc := &http.Client{
		Transport: tr,
	}
	oidcCtx := context.WithValue(b.providerCtx, oauth2.HTTPClient, tc)

	provider, err := oidc.NewProvider(oidcCtx, config.OIDCProviderURL)
	if err != nil {
		return nil, errwrap.Wrapf("error creating provider with given values: {{err}}", err)
	}

	return provider, nil
}

type oidcConfig struct {
	ClientID    string `json:"client_id"`
	SecretID    string `json:"secret_id"`
	RedirectURL string `json:"redirect_url"`
	OIDCProviderURL string `json:"oidc_discovery_url"`
	OIDCDiscoveryCAPEM   string   `json:"oidc_discovery_ca_pem"`
	Scopes      []string `json:"scopes"`
	TTL          time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL       time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
}

func (c *oidcConfig) config2OauthConfig(provider *oidc.Provider) oauth2.Config {
	conf := oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.SecretID,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  c.RedirectURL,
		Scopes:       c.Scopes,
	}
	return conf
}

const (
	confHelpSyn = `
Configures the OpenID Connect authentication backend.
`
	confHelpDesc = `
The JWT authentication backend validates JWTs (or OIDC) using the configured
credentials. If using OIDC Discovery, the URL must be provided, along
with (optionally) the CA cert to use for the connection. If performing JWT
validation locally, a set of public keys must be provided.
`
)
