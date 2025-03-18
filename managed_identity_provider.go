package entraid

import (
	"context"
	"errors"
	"fmt"
	"time"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

type ManagedIdentityProviderOptions struct {
	// UserAssignedClientID is the client ID of the user assigned identity.
	// This is used to identify the identity when requesting a token.
	UserAssignedClientID string
	// ManagedIdentityType is the type of managed identity.
	// This can be either SystemAssigned or UserAssigned.
	ManagedIdentityType string
	// Scopes is a list of scopes that the identity has access to.
	// This is used to specify the permissions that the identity has when requesting a token.
	Scopes []string
}

type ManagedIdentityProvider struct {
	// userAssignedClientID is the client ID of the user assigned identity.
	// This is used to identify the identity when requesting a token.
	userAssignedClientID string

	// managedIdentityType is the type of managed identity.
	// This can be either SystemAssigned or UserAssigned.
	managedIdentityType string

	// scopes is a list of scopes that the identity has access to.
	// This is used to specify the permissions that the identity has when requesting a token.
	scopes []string

	// client is the managed identity client used to request a token.
	client *mi.Client
}

func NewManagedIdentityProvider(opts ManagedIdentityProviderOptions) (*ManagedIdentityProvider, error) {
	var client mi.Client
	var err error

	if opts.ManagedIdentityType != SystemAssignedIdentity && opts.ManagedIdentityType != UserAssignedIdentity {
		return nil, errors.New("invalid managed identity type")
	}

	switch opts.ManagedIdentityType {
	case SystemAssignedIdentity:
		// SystemAssignedIdentity is the type of identity that is automatically managed by Azure.
		// This type of identity is automatically created and managed by Azure.
		// It is used to authenticate the identity when requesting a token.
		client, err = mi.New(mi.SystemAssigned())
	case UserAssignedIdentity:
		// UserAssignedIdentity is required to be specified when using a user assigned identity.
		if opts.UserAssignedClientID == "" {
			return nil, errors.New("user assigned client ID is required when using user assigned identity")
		}
		// UserAssignedIdentity is the type of identity that is managed by the user.
		client, err = mi.New(mi.UserAssignedClientID(opts.UserAssignedClientID))
	}

	if err != nil {
		return nil, fmt.Errorf("couldn't create managed identity client: %w", err)
	}

	return &ManagedIdentityProvider{
		userAssignedClientID: opts.UserAssignedClientID,
		managedIdentityType:  opts.ManagedIdentityType,
		scopes:               opts.Scopes,
		client:               &client,
	}, nil
}

func (m *ManagedIdentityProvider) RequestToken() (string, time.Time, error) {
	if m.client == nil {
		return "", time.Time{}, errors.New("managed identity client is not initialized")
	}

	// default resource is RedisResource == "https://redis.azure.com"
	// if no scopes are provided, use the default resource
	// if scopes are provided, use the first scope as the resource
	resource := RedisResource
	if len(m.scopes) > 0 {
		resource = m.scopes[0]
	}
	// acquire token using the managed identity client
	// the resource is the URL of the resource that the identity has access to
	token, err := m.client.AcquireToken(context.TODO(), resource)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("coudn't acquire token: %w", err)
	}

	// return the access token
	return token.AccessToken, token.ExpiresOn.UTC(), nil
}
