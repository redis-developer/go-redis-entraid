package entraid

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// DefaultAzureIdentityProviderOptions represents the options for the DefaultAzureIdentityProvider.
type DefaultAzureIdentityProviderOptions struct {
	// AzureOptions is the options used to configure the Azure identity provider.
	AzureOptions *azidentity.DefaultAzureCredentialOptions
	// Scopes is the list of scopes used to request a token from the identity provider.
	Scopes []string
}

type DefaultAzureIdentityProvider struct {
	options *azidentity.DefaultAzureCredentialOptions
	scopes  []string
}

// NewDefaultAzureIdentityProvider creates a new DefaultAzureIdentityProvider.
func NewDefaultAzureIdentityProvider(opts DefaultAzureIdentityProviderOptions) (*DefaultAzureIdentityProvider, error) {
	if opts.Scopes == nil {
		opts.Scopes = []string{RedisScopeDefault}
	}

	return &DefaultAzureIdentityProvider{options: opts.AzureOptions, scopes: opts.Scopes}, nil
}

// RequestToken requests a token from the Azure Default Identity provider.
// It returns the token, the expiration time, and an error if any.
func (a *DefaultAzureIdentityProvider) RequestToken() (IdentityProviderResponse, error) {
	cred, err := azidentity.NewDefaultAzureCredential(a.options)
	if err != nil {
		return nil, fmt.Errorf("failed to create default azure credential: %w", err)
	}

	token, err := cred.GetToken(context.TODO(), policy.TokenRequestOptions{Scopes: a.scopes})
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	return NewIDPResponse(ResponseTypeAccessToken, &token)
}
