package entraid

import (
	"time"

	"github.com/redis/go-redis/v9/auth"
)

// Token represents the authentication token used to access the Entraid API.
// It contains the username, password, expiration time, time to live, and the raw token.
// The token is used to authenticate the user and authorize access to the API.
// The token is typically obtained from an identity provider and is used to access the Entraid API.
// The token is valid for a limited time and must be refreshed periodically.
type Token struct {
	// username is the username of the user.
	username string
	// password is the password of the user.
	password string
	// expiresOn is the expiration time of the token.
	expiresOn time.Time
	// ttl is the time to live of the token.
	ttl int64
	// rawToken is the authentication token.
	rawToken string
	// receivedAt is the time when the token was received.
	receivedAt time.Time
}

// BasicAuth returns the username and password for basic authentication.
// It implements the auth.Credentials interface.
func (t *Token) BasicAuth() (string, string) {
	return t.username, t.password
}

// RawCredentials returns the raw credentials for authentication.
// It implements the auth.Credentials interface.
func (t *Token) RawCredentials() string {
	return t.rawToken
}

// ExpirationOn returns the expiration time of the token.
func (t *Token) ExpirationOn() time.Time {
	return t.expiresOn
}

// Token implements the auth.Credentials interface.
var _ auth.Credentials = (*Token)(nil)

// NewToken creates a new token with the specified username, password, raw token, expiration time, received at time, and time to live.
func NewToken(username, password, rawToken string, expiresOn, receivedAt time.Time, ttl int64) *Token {
	return &Token{
		username:   username,
		password:   password,
		expiresOn:  expiresOn,
		receivedAt: receivedAt,
		ttl:        ttl,
		rawToken:   rawToken,
	}
}

// copyToken creates a copy of the token.
func copyToken(token *Token) *Token {
	return NewToken(token.username, token.password, token.rawToken, token.expiresOn, token.receivedAt, token.ttl)
}

// compareCredentials two tokens if they are the same credentials
func (t *Token) compareCredentials(token *Token) bool {
	return t.username == token.username && t.password == token.password
}

// compareRawCredentials two tokens if they are the same raw credentials
func (t *Token) compareRawCredentials(token *Token) bool {
	return t.rawToken == token.rawToken
}

// compareToken compares two tokens if they are the same token
func (t *Token) compareToken(token *Token) bool {
	return t.compareCredentials(token) && t.compareRawCredentials(token)
}
