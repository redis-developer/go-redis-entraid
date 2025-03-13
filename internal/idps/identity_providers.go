package idps

import "fmt"

type IdentityProviderType string

var ErrUnimplemented = fmt.Errorf("identity provider not implemented")

const (
	ManagedIdentity        IdentityProviderType = "managed-identity"
	DefaultAzureCredential IdentityProviderType = "default-azure-credentials"
	ServicePrincipal       IdentityProviderType = "service-principal"
)
