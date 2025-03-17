package entraid

type IdentityProvider interface {
	// RequestToken requests a token from the identity provider.
	RequestToken() (string, error)
}
