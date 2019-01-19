package oidc

import (
	"context"
	"github.com/patrickmn/go-cache"
	"sync"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	configPath string = "config"
	callbackPath string = "callback"
	claimsConfigPath string = "claims"
)



// Factory is used by framework
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

type openIDConnectAuthBackend struct {
	*framework.Backend

	l                  sync.RWMutex
	stateCache         *cache.Cache
	provider           *oidc.Provider
	cachedConfig       *oidcConfig
	cachedClaimsConfig *oidcClaimsConfig

	providerCtx       context.Context
	providerCtxCancel context.CancelFunc
}

func backend(c *logical.BackendConfig) *openIDConnectAuthBackend {
	b := new(openIDConnectAuthBackend)
	b.providerCtx, b.providerCtxCancel = context.WithCancel(context.Background())

	b.stateCache = cache.New(5*time.Minute, 10*time.Minute)
	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		Invalidate:  b.invalidate,
		Help:        backendHelp,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
				"callback",
			},
			SealWrapStorage: []string{
				"config",
				"secret-id",
				"claims-config",
			},

		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathLogin(b),
				pathCallback(b),
				pathConfig(b),
				pathSecretID(b),
				pathClaimsConfig(b),
			},
		),
		Clean: b.cleanup,
	}

	return b
}

func (b *openIDConnectAuthBackend) cleanup(_ context.Context) {
	b.l.Lock()
	if b.providerCtxCancel != nil {
		b.providerCtxCancel()
	}
	b.l.Unlock()
}

func (b *openIDConnectAuthBackend) invalidate(ctx context.Context, key string) {
	switch key {
	case "config":
		b.reset()
	case "claims":
		b.reset()
	}
}

func (b *openIDConnectAuthBackend) reset() {
	b.l.Lock()
	b.provider = nil
	b.cachedConfig = nil
	b.cachedClaimsConfig = nil
	b.stateCache.Flush()
	b.l.Unlock()
}

func (b *openIDConnectAuthBackend) getProvider(ctx context.Context, config *oidcConfig) (*oidc.Provider, error) {
	b.l.RLock()
	unlockFunc := b.l.RUnlock
	defer func() { unlockFunc() }()

	if b.provider != nil {
		return b.provider, nil
	}

	b.l.RUnlock()
	b.l.Lock()
	unlockFunc = b.l.Unlock

	if b.provider != nil {
		return b.provider, nil
	}

	provider, err := b.createProvider(config)
	if err != nil {
		return nil, err
	}

	b.provider = provider
	return provider, nil
}

const (
	backendHelp = `
The OpenID Connect backend plugin allows authentication using OpenID code flow.
`
)