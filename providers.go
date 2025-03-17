package entraid

import (
	"crypto"
	"crypto/x509"

	"github.com/redis/go-redis/v9/auth"
)

type CredentialsProviderOptions struct {
	// ClientID is the client ID of the system assigned identity.
	// This is used to identify the identity when requesting a token.
	ClientID string

	// TenantID is the tenant ID of the service principal.
	// This is used to identify the tenant when requesting a token.
	TenantID string

	// Scopes is a list of scopes that the identity has access to.
	// This is used to specify the permissions that the identity has when requesting a token.
	Scopes []string

	// TokenManagerOptions is the options for the token manager.
	// This is used to configure the token manager when requesting a token.
	TokenManagerOptions TokenManagerOptions

	// OnReAuthenticationError is a callback function that is called when a re-authentication error occurs.
	OnReAuthenticationError func(error) error

	// OnRetryableError is a callback function that is called when a retryable error occurs.
	OnRetryableError func(error) error
}

const (
	// SystemAssignedIdentity is the type of identity that is automatically managed by Azure.
	SystemAssignedIdentity = "SystemAssigned"
	// UserAssignedIdentity is the type of identity that is managed by the user.
	UserAssignedIdentity = "UserAssigned"

	// ClientSecretCredentialType is the type of credentials that uses a client secret to authenticate.
	ClientSecretCredentialType = "ClientSecret"
	// ClientCertificateCredentialType is the type of credentials that uses a client certificate to authenticate.
	ClientCertificateCredentialType = "ClientCertificate"

	// RedisScopeDefault is the default scope for Redis.
	// This is used to specify the scope that the identity has access to when requesting a token.
	// The scope is typically the URL of the resource that the identity has access to.
	RedisScopeDefault = "https://redis.azure.com/.default"

	// RedisResource is the default resource for Redis.
	// This is used to specify the resource that the identity has access to when requesting a token.
	// The resource is typically the URL of the resource that the identity has access to.
	RedisResource = "https://redis.azure.com"
)

// Managed identity type

// ManagedIdentityCredentialsProviderOptions is a struct that holds the options for the managed identity credentials provider.
type ManagedIdentityCredentialsProviderOptions struct {
	CredentialsProviderOptions
	// ManagedIdentityType is the type of managed identity to use.
	// This can be either SystemAssigned or UserAssigned.
	ManagedIdentityType string

	// UserAssignedClientID is the client ID of the user assigned identity.
	UserAssignedClientID string
}

// NewManagedIdentityCredentialsProvider creates a new streaming credentials provider for managed identity.
// It uses the provided options to configure the provider.
// Use this when you want either a system assigned identity or a user assigned identity.
// The system assigned identity is automatically managed by Azure and does not require any additional configuration.
// The user assigned identity is a separate resource that can be managed independently.
func NewManagedIdentityCredentialsProvider(options ManagedIdentityCredentialsProviderOptions) (auth.StreamingCredentialsProvider, error) {
	// Create a new identity provider using the managed identity type.
	idp, err := NewManagedIdentityProvider(ManagedIdentityProviderOptions{
		ManagedIdentityType:  options.ManagedIdentityType,
		UserAssignedClientID: options.UserAssignedClientID,
	})
	if err != nil {
		return nil, err
	}

	// Create a new token manager using the identity provider.
	tokenManager := NewTokenManager(idp, options.TokenManagerOptions)
	// Create a new credentials provider using the token manager.
	credentialsProvider, err := newCredentialsProvider(tokenManager, CredentialsProviderOptions{
		ClientID:                options.ClientID,
		TenantID:                options.TenantID,
		Scopes:                  options.Scopes,
		OnReAuthenticationError: options.OnReAuthenticationError,
		OnRetryableError:        options.OnRetryableError,
	})
	if err != nil {
		return nil, err
	}

	return credentialsProvider, nil
}

// Service Principal Credentials Provider below

type ServicePrincipalCredentialsProviderOptions struct {
	CredentialsProviderOptions

	// ClientCredentialType is the type of credentials that are used to authenticate the service principal.
	// This can be either ClientSecret or ClientCertificate.
	// ClientSecret is used to authenticate the service principal when requesting a token.
	// ClientCertificate is used to authenticate the service principal using a certificate.
	ClientCredentialType string

	// ClientSecret is the client secret of the service principal.
	// This is used to authenticate the service principal when requesting a token.
	ClientSecret string

	// ClientCertificate is the client certificate of the service principal.
	// This is used to authenticate the service principal when requesting a token.
	ClientCertificate x509.Certificate
	// ClientCertificatePrivateKey is the private key of the client certificate.
	// This is used to authenticate the service principal when requesting a token.
	ClientCertificatePrivateKey crypto.PrivateKey
}

// NewServicePrincipalCredentialsProvider creates a new streaming credentials provider for service principal.
// It uses the provided options to configure the provider.
// Use this when you want to use a service principal to authenticate with Azure.
// The service principal is a security identity that is used to authenticate with Azure.
// It is typically used in scenarios where a user cannot be present to authenticate interactively.
// The service principal is created in Azure Active Directory and is used to authenticate with Azure resources.
func NewServicePrincipalCredentialsProvider(options ServicePrincipalCredentialsProviderOptions) (auth.StreamingCredentialsProvider, error) {

	idp, err := NewMSALIdentityProvider(MSALIdentityProviderOptions{
		ClientID:     options.ClientID,
		ClientSecret: options.ClientSecret,
	})

	tokenManager := NewTokenManager(idp, options.TokenManagerOptions)

	// Create a new credentials provider using the token manager.
	credentialsProvider, err := newCredentialsProvider(tokenManager, CredentialsProviderOptions{
		ClientID:                options.ClientID,
		TenantID:                options.TenantID,
		Scopes:                  options.Scopes,
		OnReAuthenticationError: options.OnReAuthenticationError,
		OnRetryableError:        options.OnRetryableError,
	})
	return credentialsProvider, ErrNotImplemented
}
