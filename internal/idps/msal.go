package idps

import "github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"

// MSALIdentityProviderOptions is a struct that holds the options for the MSAL identity provider.
// It contains the ClientID which is used to initialize the MSAL client.
// The ClientID is a unique identifier for the application registered in Azure AD.
// The MSAL client is used to request tokens from the Microsoft identity platform.
type MSALIdentityProviderOptions struct {
	// ClientID is the unique identifier for the application registered in Azure AD.
	ClientID string
	// ClientSecret is the secret key for the application registered in Azure AD.
	ClientSecret string
}

// MSALIdentityProvider is a struct that implements the IdentityProvider interface.
type MSALIdentityProvider struct {
	client  public.Client
	idpType IdentityProviderType
}

func (m *MSALIdentityProvider) getToken() (string, error) {
	// This method is not implemented yet.
	return "", ErrNotImplemented
}

// requestToken requests a token from the MSAL identity provider.
func (m *MSALIdentityProvider) requestToken() (string, error) {
	return "", ErrNotImplemented
}

// NewMSALIdentityProvider creates a new MSALIdentityProvider with the given options.
// It initializes the MSAL client with the provided ClientID.
func NewMSALIdentityProvider(options MSALIdentityProviderOptions) (*MSALIdentityProvider, error) {
	client, err := public.New(options.ClientID)
	if err != nil {
		return nil, err
	}

	return &MSALIdentityProvider{
		client: client,
	}, nil
}
