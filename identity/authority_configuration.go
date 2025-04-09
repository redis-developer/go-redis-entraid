package identity

import "fmt"

const (
	// AuthorityTypeDefault is the default authority type.
	// This is used to specify the authority type when requesting a manager.
	AuthorityTypeDefault = "default"
	// AuthorityTypeMultiTenant is the multi-tenant authority type.
	// This is used to specify the multi-tenant authority type when requesting a manager.
	// This type of authority is used to authenticate the identity when requesting a manager.
	AuthorityTypeMultiTenant = "multi-tenant"
	// AuthorityTypeCustom is the custom authority type.
	// This is used to specify the custom authority type when requesting a manager.
	AuthorityTypeCustom = "custom"
)

// AuthorityConfiguration represents the authority configuration for the identity provider.
// It is used to configure the authority type and authority URL when requesting a manager.
type AuthorityConfiguration struct {
	// AuthorityType is the type of authority used to authenticate with the identity provider.
	// This can be either "default", "multi-tenant", or "custom".
	AuthorityType string

	// Authority is the authority used to authenticate with the identity provider.
	// This is typically the URL of the identity provider.
	// For example, "https://login.microsoftonline.com/{tenantID}/v2.0"
	Authority string

	// TenantID is the tenant ID of the identity provider.
	// This is used to identify the tenant when requesting a manager.
	// This is typically the ID of the Azure Active Directory tenant.
	TenantID string
}

// getAuthority returns the authority URL based on the authority type.
// The authority type can be either "default", "multi-tenant", or "custom".
func (a AuthorityConfiguration) getAuthority() (string, error) {
	if a.AuthorityType == "" {
		a.AuthorityType = AuthorityTypeDefault
	}

	switch a.AuthorityType {
	case AuthorityTypeDefault:
		return "https://login.microsoftonline.com/common", nil
	case AuthorityTypeMultiTenant:
		if a.TenantID == "" {
			return "", fmt.Errorf("tenant ID is required when using multi-tenant authority type")
		}
		return fmt.Sprintf("https://login.microsoftonline.com/%s", a.TenantID), nil
	case AuthorityTypeCustom:
		if a.Authority == "" {
			return "", fmt.Errorf("authority is required when using custom authority type")
		}
		return a.Authority, nil
	default:
		return "", fmt.Errorf("invalid authority type: %s", a.AuthorityType)
	}
}
