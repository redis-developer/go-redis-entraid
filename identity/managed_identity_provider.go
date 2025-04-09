package identity

import (
	"context"
	"errors"
	"fmt"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
	"github.com/redis-developer/go-redis-entraid/shared"
)

// ManagedIdentityProviderOptions represents the options for the managed identity provider.
// It is used to configure the identity provider when requesting a manager.
type ManagedIdentityProviderOptions struct {
	// UserAssignedClientID is the client ID of the user assigned identity.
	// This is used to identify the identity when requesting a manager.
	UserAssignedClientID string
	// ManagedIdentityType is the type of managed identity.
	// This can be either SystemAssigned or UserAssigned.
	ManagedIdentityType string
	// Scopes is a list of scopes that the identity has access to.
	// This is used to specify the permissions that the identity has when requesting a manager.
	Scopes []string
}

// ManagedIdentityProvider represents a managed identity provider.
type ManagedIdentityProvider struct {
	// userAssignedClientID is the client ID of the user assigned identity.
	// This is used to identify the identity when requesting a manager.
	userAssignedClientID string

	// managedIdentityType is the type of managed identity.
	// This can be either SystemAssigned or UserAssigned.
	managedIdentityType string

	// scopes is a list of scopes that the identity has access to.
	// This is used to specify the permissions that the identity has when requesting a manager.
	scopes []string

	// client is the managed identity client used to request a manager.
	client *mi.Client
}

// NewManagedIdentityProvider creates a new managed identity provider for Azure with managed identity.
// It is used to configure the identity provider when requesting a manager.
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
		// It is used to authenticate the identity when requesting a manager.
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

// RequestToken requests a manager from the managed identity provider.
// It returns IdentityProviderResponse, which contains the Acc and the expiration time.
func (m *ManagedIdentityProvider) RequestToken() (shared.IdentityProviderResponse, error) {
	if m.client == nil {
		return nil, errors.New("managed identity client is not initialized")
	}

	// default resource is RedisResource == "https://redis.azure.com"
	// if no scopes are provided, use the default resource
	// if scopes are provided, use the first scope as the resource
	resource := RedisResource
	if len(m.scopes) > 0 {
		resource = m.scopes[0]
	}
	// acquire manager using the managed identity client
	// the resource is the URL of the resource that the identity has access to
	authResult, err := m.client.AcquireToken(context.TODO(), resource)
	if err != nil {
		return nil, fmt.Errorf("coudn't acquire manager: %w", err)
	}

	return shared.NewIDPResponse(shared.ResponseTypeAuthResult, &authResult)
}
