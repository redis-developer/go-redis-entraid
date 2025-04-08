package entraid

import (
	"fmt"

	"github.com/redis/go-redis/v9/auth"
)

// CredentialsProviderOptions is a struct that holds the options for the credentials provider.
// It is used to configure the credentials provider when requesting a token.
// It is used to specify the client ID, TokenManagerOptions, and callback functions for re-authentication and retriable errors.
type CredentialsProviderOptions struct {
	// ClientID is the client ID of the identity.
	// This is used to identify the identity when requesting a token.
	ClientID string

	// TokenManagerOptions is the options for the token manager.
	// This is used to configure the token manager when requesting a token.
	TokenManagerOptions TokenManagerOptions

	// OnReAuthenticationError is a callback function that is called when a re-authentication error occurs.
	OnReAuthenticationError func(error) error

	// OnRetryableError is a callback function that is called when a retriable error occurs.
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
	// CredentialsProviderOptions is the options for the credentials provider.
	// This is used to configure the credentials provider when requesting a token.
	// It is used to specify the client ID, tenant ID, and scopes for the identity.
	CredentialsProviderOptions

	// ManagedIdentityProviderOptions is the options for the managed identity provider.
	// This is used to configure the managed identity provider when requesting a token.
	ManagedIdentityProviderOptions
}

// NewManagedIdentityCredentialsProvider creates a new streaming credentials provider for managed identity.
// It uses the provided options to configure the provider.
// Use this when you want either a system assigned identity or a user assigned identity.
// The system assigned identity is automatically managed by Azure and does not require any additional configuration.
// The user assigned identity is a separate resource that can be managed independently.
func NewManagedIdentityCredentialsProvider(options ManagedIdentityCredentialsProviderOptions) (auth.StreamingCredentialsProvider, error) {
	// Create a new identity provider using the managed identity type.
	idp, err := NewManagedIdentityProvider(options.ManagedIdentityProviderOptions)
	if err != nil {
		return nil, fmt.Errorf("cannot create managed identity provider: %w", err)
	}

	// Create a new token manager using the identity provider.
	tokenManager, err := NewTokenManager(idp, options.TokenManagerOptions)
	if err != nil {
		return nil, fmt.Errorf("cannot create token manager: %w", err)
	}
	// Create a new credentials provider using the token manager.
	credentialsProvider, err := newCredentialsProvider(tokenManager, options.CredentialsProviderOptions)
	if err != nil {
		return nil, fmt.Errorf("cannot create credentials provider: %w", err)
	}

	return credentialsProvider, nil
}

// ConfidentialCredentialsProviderOptions is a struct that holds the options for the confidential credentials provider.
// It is used to configure the credentials provider when requesting a token.
type ConfidentialCredentialsProviderOptions struct {
	// CredentialsProviderOptions is the options for the credentials provider.
	// This is used to configure the credentials provider when requesting a token.
	CredentialsProviderOptions

	// ConfidentialIdentityProviderOptions is the options for the confidential identity provider.
	// This is used to configure the identity provider when requesting a token.
	ConfidentialIdentityProviderOptions
}

// NewConfidentialCredentialsProvider creates a new confidential credentials provider.
// It uses client id and client credentials to authenticate with the identity provider.
// The client credentials can be either a client secret or a client certificate.
func NewConfidentialCredentialsProvider(options ConfidentialCredentialsProviderOptions) (auth.StreamingCredentialsProvider, error) {
	// Create a new identity provider using the client ID and client credentials.
	idp, err := NewConfidentialIdentityProvider(options.ConfidentialIdentityProviderOptions)
	if err != nil {
		return nil, fmt.Errorf("cannot create confidential identity provider: %w", err)
	}

	// Create a new token manager using the identity provider.
	tokenManager, err := NewTokenManager(idp, options.TokenManagerOptions)
	if err != nil {
		return nil, fmt.Errorf("cannot create token manager: %w", err)
	}

	// Create a new credentials provider using the token manager.
	credentialsProvider, err := newCredentialsProvider(tokenManager, options.CredentialsProviderOptions)
	if err != nil {
		return nil, fmt.Errorf("cannot create credentials provider: %w", err)
	}
	return credentialsProvider, nil
}

// DefaultAzureCredentialsProviderOptions is a struct that holds the options for the default azure credentials provider.
// It is used to configure the credentials provider when requesting a token.
type DefaultAzureCredentialsProviderOptions struct {
	CredentialsProviderOptions
	DefaultAzureIdentityProviderOptions
}

// NewDefaultAzureCredentialsProvider creates a new default azure credentials provider.
// It uses the default azure identity provider to authenticate with the identity provider.
// The default azure identity provider is a special type of identity provider that uses the default azure identity to authenticate.
// It is used to authenticate with the identity provider when requesting a token.
func NewDefaultAzureCredentialsProvider(options DefaultAzureCredentialsProviderOptions) (auth.StreamingCredentialsProvider, error) {
	// Create a new identity provider using the default azure identity type.
	idp, err := NewDefaultAzureIdentityProvider(options.DefaultAzureIdentityProviderOptions)
	if err != nil {
		return nil, fmt.Errorf("cannot create default azure identity provider: %w", err)
	}

	// Create a new token manager using the identity provider.
	tokenManager, err := NewTokenManager(idp, options.TokenManagerOptions)
	if err != nil {
		return nil, fmt.Errorf("cannot create token manager: %w", err)
	}

	// Create a new credentials provider using the token manager.
	credentialsProvider, err := newCredentialsProvider(tokenManager, options.CredentialsProviderOptions)
	if err != nil {
		return nil, fmt.Errorf("cannot create credentials provider: %w", err)
	}
	return credentialsProvider, nil

}
