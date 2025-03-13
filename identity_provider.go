package entraid

type IdentityProvider interface {
	// requestToken requests a token from the identity provider.
	requestToken() (string, error)
}
