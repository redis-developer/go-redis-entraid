package entraid

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	confidential "github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

import "crypto/x509"

const (
	// AuthorityTypeDefault is the default authority type.
	// This is used to specify the authority type when requesting a token.
	AuthorityTypeDefault = "default"
	// AuthorityTypeMultiTenant is the multi-tenant authority type.
	// This is used to specify the multi-tenant authority type when requesting a token.
	// This type of authority is used to authenticate the identity when requesting a token.
	AuthorityTypeMultiTenant = "multi-tenant"
	// AuthorityTypeCustom is the custom authority type.
	// This is used to specify the custom authority type when requesting a token.
	AuthorityTypeCustom = "custom"
)

type AuthorityConfiguration struct {
	// AuthorityType is the type of authority used to authenticate with the identity provider.
	// This can be either "default", "multi-tenant", or "custom".
	AuthorityType string

	// Authority is the authority used to authenticate with the identity provider.
	// This is typically the URL of the identity provider.
	// For example, "https://login.microsoftonline.com/{tenantID}/v2.0"
	Authority string

	// TenantID is the tenant ID of the identity provider.
	// This is used to identify the tenant when requesting a token.
	// This is typically the ID of the Azure Active Directory tenant.
	TenantID string
}

func (a AuthorityConfiguration) GetAuthority() (string, error) {
	if a.AuthorityType == "" {
		a.AuthorityType = AuthorityTypeDefault
	}

	switch a.AuthorityType {
	case AuthorityTypeDefault:
		return "https://login.microsoftonline.com/common", nil
	case AuthorityTypeMultiTenant:
		if a.TenantID == "" {
			return "", errors.New("tenant ID is required when using multi-tenant authority type")
		}
		return fmt.Sprintf("https://login.microsoftonline.com/%s", a.TenantID), nil
	case AuthorityTypeCustom:
		if a.Authority == "" {
			return "", errors.New("authority is required when using custom authority type")
		}
		return a.Authority, nil
	default:
		return "", errors.New("invalid authority type")
	}
}

type ConfidentialIdentityProvider struct {
	// clientID is the client ID used to authenticate with the identity provider.
	clientID string

	// credential is the credential used to authenticate with the identity provider.
	credential confidential.Credential

	// scopes is the list of scopes used to request a token from the identity provider.
	scopes []string

	// client confidential is the client used to request a token from the identity provider.
	client *confidential.Client
}

type ConfidentialIdentityProviderOptions struct {
	// ClientID is the client ID used to authenticate with the identity provider.
	ClientID string

	// CredentialsType is the type of credentials used to authenticate with the identity provider.
	// This can be either "ClientSecret" or "ClientCertificate".
	CredentialsType string

	// ClientSecret is the client secret used to authenticate with the identity provider.
	ClientSecret string

	// ClientCert is the client certificate used to authenticate with the identity provider.
	ClientCert []*x509.Certificate
	// ClientPrivateKey is the private key used to authenticate with the identity provider.
	ClientPrivateKey crypto.PrivateKey

	// Scopes is the list of scopes used to request a token from the identity provider.
	Scopes []string

	// Authority is the authority used to authenticate with the identity provider.
	Authority AuthorityConfiguration
}

func NewConfidentialIdentityProvider(opts ConfidentialIdentityProviderOptions) (*ConfidentialIdentityProvider, error) {
	var credential confidential.Credential
	var authority string
	var err error

	if opts.ClientID == "" {
		return nil, errors.New("client ID is required")
	}

	if opts.CredentialsType != ClientSecretCredentialType && opts.CredentialsType != ClientCertificateCredentialType {
		return nil, errors.New("invalid credentials type")
	}

	// Get the authority from the authority configuration.
	authority, err = opts.Authority.GetAuthority()
	if err != nil {
		return nil, fmt.Errorf("failed to get authority: %w", err)
	}

	switch opts.CredentialsType {
	case ClientSecretCredentialType:
		// ClientSecretCredentialType is the type of credentials that uses a client secret to authenticate.
		if opts.ClientSecret == "" {
			return nil, errors.New("client secret is required when using client secret credentials")
		}

		credential, err = confidential.NewCredFromSecret(opts.ClientSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to create client secret credential: %w", err)
		}
	case ClientCertificateCredentialType:
		// ClientCertificateCredentialType is the type of credentials that uses a client certificate to authenticate.
		if opts.ClientCert == nil {
			return nil, errors.New("client certificate is required when using client certificate credentials")
		}
		if opts.ClientPrivateKey == nil {
			return nil, errors.New("client private key is required when using client certificate credentials")
		}
		credential, err = confidential.NewCredFromCert(opts.ClientCert, opts.ClientPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create client certificate credential: %w", err)
		}
	}

	client, err := confidential.New(authority, opts.ClientID, credential)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	if opts.Scopes == nil {
		opts.Scopes = []string{RedisScopeDefault}
	}

	return &ConfidentialIdentityProvider{
		clientID:   opts.ClientID,
		credential: credential,
		scopes:     opts.Scopes,
		client:     &client,
	}, nil
}

func (c *ConfidentialIdentityProvider) RequestToken() (string, error) {
	if c.client == nil {
		return "", errors.New("client is not initialized")
	}

	result, err := c.client.AcquireTokenByCredential(context.TODO(), c.scopes)
	if err != nil {
		return "", fmt.Errorf("failed to acquire token: %w", err)
	}

	return result.AccessToken, nil
}
