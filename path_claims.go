package oidc

import (
	"context"
	"encoding/json"
	"github.com/coreos/go-oidc"
	"github.com/go-errors/errors"
	"github.com/hashicorp/errwrap"
	"strings"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathClaimsConfig(b *openIDConnectAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: `claims$`,
		Fields: map[string]*framework.FieldSchema{
			"user_claim": {
				Type:        framework.TypeString,
				Description: `The claim to use for the Identity entity alias name`,
			},
			"groups_claim": {
				Type:        framework.TypeString,
				Description: `The claim to use for the Identity group alias names`,
			},
			"groups_delimiter": {
				Type:        framework.TypeString,
				Description: `The groups claim's data delimiter, default is comma-delimited`,
			},
			"display_name_claim": {
				Type:        framework.TypeString,
				Description: `The claim to use for the Identity entity alias display name`,
			},
			"policies_claim": {
				Type:        framework.TypeString,
				Description: `Claim to use for mapping policies with matching names to entity.`,
			},
			"policies_delimiter": {
				Type:        framework.TypeString,
				Description: `The policies claim's data delimiter, default is comma-delimited`,
			},
			"metadata_claims": {
				Type:        framework.TypeCommaStringSlice,
				Description: `Claim to use for mapping claim values to entity metadata.`,
			},
			"all_metadata": {
				Type:        framework.TypeBool,
				Description: "Flag tp map all claims into metadata",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathClaimsConfigRead,
			logical.UpdateOperation: b.pathClaimsConfigWrite,
		},

		HelpSynopsis:    claimsHelpSyn,
		HelpDescription: claimsHelpDesc,
	}
}

func (b *openIDConnectAuthBackend) claimsConfig(ctx context.Context, s logical.Storage) (*oidcClaimsConfig, error) {
	b.l.RLock()
	defer b.l.RUnlock()

	if b.cachedClaimsConfig != nil {
		return b.cachedClaimsConfig, nil
	}

	entry, err := s.Get(ctx, claimsConfigPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	result := &oidcClaimsConfig{}
	if entry != nil {
		if err := entry.DecodeJSON(result); err != nil {
			return nil, err
		}
	}

	b.cachedClaimsConfig = result

	return result, nil
}

func (b *openIDConnectAuthBackend) pathClaimsConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := b.claimsConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"user_claim":         config.UserClaim,
			"display_name_claim": config.DisplayNameClaim,
			"groups_claim":       config.GroupsClaim,
			"groups_delimiter":   config.GroupsDelimiter,
			"policies_claim":    config.PoliciesClaim,
			"policies_delimiter": config.PoliciesDelimiter,
			"all_metadata":       config.AllMetadata,
			"metadata_claims":    config.MetadataClaims,
		},
	}

	return resp, nil
}

func (b *openIDConnectAuthBackend) pathClaimsConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config := &oidcClaimsConfig{
		UserClaim:         d.Get("user_claim").(string),
		GroupsClaim:       d.Get("groups_claim").(string),
		GroupsDelimiter:   d.Get("groups_delimiter").(string),
		DisplayNameClaim:  d.Get("display_name_claim").(string),
		PoliciesClaim:     d.Get("policies_claim").(string),
		PoliciesDelimiter: d.Get("policies_delimiter").(string),
		MetadataClaims:    d.Get("metadata_claims").([]string),
		AllMetadata:       d.Get("all_metadata").(bool),
	}

	// Run checks on values
	if config.UserClaim == ""  {
		return logical.ErrorResponse("user claim must be set."), nil
	}
	if config.GroupsDelimiter == "" {
		config.GroupsDelimiter = ","
	}
	if config.DisplayNameClaim == "" {
		config.DisplayNameClaim = config.UserClaim
	}
	if config.PoliciesDelimiter == "" {
		config.PoliciesDelimiter = ","
	}

	entry, err := logical.StorageEntryJSON(claimsConfigPath, config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()

	var resp *logical.Response

	if len(config.MetadataClaims) > 0 && config.AllMetadata {
		resp = &logical.Response{
			Warnings: []string{
				"all_metadata enabled, metadata_claims will be ignored.",
			},
		}
	}

	return resp, nil
}

func (c *oidcClaimsConfig) parseUserInfo(info *oidc.UserInfo) (*UserEntry, error) {
	user := &UserEntry{}
	user.Metadata = make(map[string]string)
	var rawClaims map[string]*json.RawMessage
	err := info.Claims(&rawClaims)
	if err != nil {
		return nil, errwrap.Wrapf("failed to encode claims: {{err}}", err)
	}

	if usr, ok := rawClaims[c.UserClaim]; ok {
		user.Username =strings.Trim(string(*usr), "\"")
		user.Metadata["username"] = user.Username
	} else {
		return nil, errors.New("Failed to get user claim")
	}

	if c.GroupsClaim != "" {
		if grp, ok :=  rawClaims[c.GroupsClaim]; ok {
			user.Groups = strings.Split(strings.Trim(string(*grp), "\""), c.GroupsDelimiter)
		} else {
			return nil, errors.New("Failed to get groups claim")
		}
	}

	if c.PoliciesClaim != "" {
		if pol, ok :=  rawClaims[c.PoliciesClaim]; ok {
			user.Policies = strings.Split(strings.Trim(string(*pol), "\""), c.PoliciesDelimiter)
		} else {
			return nil, errors.New("Failed to get policies claim")
		}
	}

	if dn, ok := rawClaims[c.DisplayNameClaim]; ok {
		user.DisplayName =strings.Trim(string(*dn), "\"")
	} else {
		user.DisplayName = user.Username
	}

	err = c.parseMetadata(&rawClaims, &user.Metadata)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (c *oidcClaimsConfig) parseMetadata(claims *map[string]*json.RawMessage, metadata *map[string]string) error {
	// Add all claims to metadata
	if c.AllMetadata {
		for k, v := range *claims {
			(*metadata)[k] = strings.Trim(string(*v), "\"")
		}
	} else {
		for _, claim := range c.MetadataClaims {
			claimKey := claim
			// Check if claims mapping is configured
			if strings.Contains(claim, "=") {
				kv := strings.Split(claim, "=")
				if len(kv) != 2 {
					return errors.New("Metadata mapping policy contains to many '=' delimiters")
				}
				claim = kv[0]
				claimKey = kv[1]
			}

			if md, ok := (*claims)[claim]; ok {
				(*metadata)[claimKey] = strings.Trim(string(*md), "\"")
			}
		}
	}

	return nil
}

type UserEntry struct {
	Username	string
	DisplayName string
	Groups 		[]string
	Policies 	[]string
	Metadata    map[string]string
}

type oidcClaimsConfig struct {
	DisplayNameClaim  string   `json:"display_name_claim"`
	UserClaim         string   `json:"user_claim"`
	GroupsClaim       string   `json:"groups_claim"`
	GroupsDelimiter   string   `json:"groups_delimiter"`
	PoliciesClaim     string   `json:"policies_claim"`
	PoliciesDelimiter string   `json:"policies_delimiter"`
	MetadataClaims    []string `json:"metadata_claims"`
	AllMetadata       bool     `json:"all_metadata"`
}

const (
	claimsHelpSyn = `
Configures Claims mapping to Vault entity attributes.
`
	claimsHelpDesc = `
The JWT authentication backend validates JWTs (or OIDC) using the configured
credentials. If using OIDC Discovery, the URL must be provided, along
with (optionally) the CA cert to use for the connection. If performing JWT
validation locally, a set of public keys must be provided.
`
)
