package entraid

import "time"

// IdentityProvider is an interface that defines the methods for an identity provider.
// It is used to request a token for authentication.
// The identity provider is responsible for providing the raw authentication token.
type IdentityProvider interface {
	// RequestToken requests a token from the identity provider.
	// It returns the token, the expiration time, and an error if any.
	RequestToken() (string, time.Time, error)
}
