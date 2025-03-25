package entraid

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

const (
	// ResponseTypeAuthResult is the type of the auth result.
	ResponseTypeAuthResult = "AuthResult"
	// ResponseTypeAccessToken is the type of the access token.
	ResponseTypeAccessToken = "AccessToken"
	// ResponseTypeRawToken is the type of the response when you have a raw string.
	ResponseTypeRawToken = "RawToken"
)

// IdentityProviderResponse is an interface that defines the methods for an identity provider authentication result.
// It is used to get the type of the authentication result, the authentication result itself (can be AuthResult or AccessToken),
type IdentityProviderResponse interface {
	// Type returns the type of the auth result
	Type() string
	AuthResult() *public.AuthResult
	AccessToken() *azcore.AccessToken
	RawToken() string
}

// IdentityProviderResponseParserFunc is a function that parses the token and returns the username and password.
type IdentityProviderResponseParserFunc func(response IdentityProviderResponse) (*Token, error)

// IdentityProvider is an interface that defines the methods for an identity provider.
// It is used to request a token for authentication.
// The identity provider is responsible for providing the raw authentication token.
type IdentityProvider interface {
	// RequestToken requests a token from the identity provider.
	// It returns the token, the expiration time, and an error if any.
	RequestToken() (IdentityProviderResponse, error)
}

type authResult struct {
	resultType  string
	authResult  *public.AuthResult
	accessToken *azcore.AccessToken
	rawToken    string
}

func (a *authResult) Type() string {
	return a.resultType
}

func (a *authResult) AuthResult() *public.AuthResult {
	return a.authResult
}

func (a *authResult) AccessToken() *azcore.AccessToken {
	return a.accessToken
}

func (a *authResult) RawToken() string {
	return a.rawToken
}

// NewIDPResponse creates a new auth result based on the type provided.
// It returns an IdentityProviderResponse interface.
func NewIDPResponse(t string, result interface{}) (IdentityProviderResponse, error) {
	r := &authResult{resultType: t}

	switch t {
	case ResponseTypeAuthResult:
		if typed, ok := result.(*public.AuthResult); !ok {
			return nil, fmt.Errorf("expected AuthResult, got %T", result)
		} else {
			r.authResult = typed
		}
	case ResponseTypeAccessToken:
		if typed, ok := result.(*azcore.AccessToken); !ok {
			return nil, fmt.Errorf("expected AccessToken, got %T", result)
		} else {
			r.accessToken = typed
		}
	case ResponseTypeRawToken:
		if typed, ok := result.(string); !ok {
			return nil, fmt.Errorf("expected string, got %T", result)
		} else {
			r.rawToken = typed
		}
	default:
		return nil, fmt.Errorf("unknown idp response type: %s", t)
	}

	return r, nil
}
