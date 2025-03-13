package entraid

// Token represents the authentication token used to access the Entraid API.
// It contains the username, password, expiration time, time to live, and the raw token.
// The token is used to authenticate the user and authorize access to the API.
// The token is typically obtained from an identity provider and is used to access the Entraid API.
// The token is valid for a limited time and must be refreshed periodically.
type Token struct {
	// Username is the username of the user.
	Username string `json:"username"`
	// Password is the password of the user.
	Password string `json:"password"`
	// ExpiresAt is the expiration time of the token.
	ExpiresAt int64 `json:"expires_at"`
	// TTL is the time to live of the token.
	TTL int64 `json:"ttl"`
	// RawToken is the authentication token.
	RawToken string `json:"raw_token"`
}

// TokenParserFunc is a function that parses the token and returns the username and password.
type TokenParserFunc func(token string) (*Token, error)

// copyToken creates a copy of the token.
func copyToken(token *Token) *Token {
	return &Token{
		Username:  token.Username,
		Password:  token.Password,
		ExpiresAt: token.ExpiresAt,
		TTL:       token.TTL,
		RawToken:  token.RawToken,
	}
}
