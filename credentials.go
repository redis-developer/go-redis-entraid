package entraid

import (
	auth "github.com/redis/go-redis/v9/auth"
)

// authCredentials implements the auth.Credentials interface.
var _ auth.Credentials = (*authCredentials)(nil)

// authCredentials represents the authentication credentials used to access the Entraid API.
// It contains the username, password, and raw credentials.
// The authCredentials struct is used to store the authentication credentials
type authCredentials struct {
	username       string
	password       string
	rawCredentials string
}

// BasicAuth returns the username and password for basic authentication.
func (a *authCredentials) BasicAuth() (username string, password string) {
	return a.username, a.password
}

// RawCredentials returns the raw credentials for authentication.
func (a *authCredentials) RawCredentials() string {
	return a.rawCredentials
}
