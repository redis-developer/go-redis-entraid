package entraid

import (
	"github.com/redis/go-redis/v9/auth"
)

type CredentialsProviderOptions struct {
	// ClientID is the client ID of the system assigned identity.
	// This is used to identify the identity when requesting a token.
	ClientID string

	// Scopes is a list of scopes that the identity has access to.
	// This is used to specify the permissions that the identity has when requesting a token.
	Scopes []string

	TokenManagerOptions TokenManagerOptions
	// rewrite to go

	// OnReAuthenticationError is a callback function that is called when a re-authentication error occurs.
	OnReAuthenticationError func(error) error

	// OnRetryableError is a callback function that is called when a retryable error occurs.
	OnRetryableError func(error) error
}

type SystemAssignedOptions struct {
	CredentialsProviderOptions
}

func NewSystemAssignedCredentialsProvider(options SystemAssignedOptions) (auth.StreamingCredentialsProvider, error) {
	return nil, ErrNotImplemented
}

type UserAssignedOptions struct {
	CredentialsProviderOptions
}

func NewUserAssignedCredentialsProvider(options UserAssignedOptions) (auth.StreamingCredentialsProvider, error) {
	return nil, ErrNotImplemented
}

type ClientCredentialsOptions struct {
	CredentialsProviderOptions
}

func NewClientCredentialsCredentialsProvider(options ClientCredentialsOptions) (auth.StreamingCredentialsProvider, error) {
	return nil, ErrNotImplemented
}

type DefaultAzureOptions struct {
	CredentialsProviderOptions
}

func NewDefaultAzureCredentialsProvider(options DefaultAzureOptions) (auth.StreamingCredentialsProvider, error) {
	return nil, ErrNotImplemented
}

type AuthorizationCodeWithPKCEOptions struct {
	CredentialsProviderOptions
}

func NewAuthorizationCodeWithPKCECredentialsProvider(options AuthorizationCodeWithPKCEOptions) (auth.StreamingCredentialsProvider, error) {
	return nil, ErrNotImplemented
}
