package entraid

import (
	"fmt"
	"time"
)

// TokenManagerOptions is a struct that contains the options for the TokenManager.
type TokenManagerOptions struct {
	ParseToken TokenParserFunc
}

// TokenManager is an interface that defines the methods for managing tokens.
// It provides methods to get a token and start the token manager.
// The TokenManager is responsible for obtaining and refreshing the token.
// It is typically used in conjunction with an IdentityProvider to obtain the token.
type TokenManager interface {
	// GetToken returns the token for authentication.
	GetToken() (*Token, error)
	// Start starts the token manager and returns a channel that will receive updates.
	Start(listener TokenListener) (cancelFunc, error)
}

// defaultTokenParser is a function that parses the raw token and returns Token object.
var defaultTokenParser = func(rawToken string) (*Token, error) {
	// Parse the token and return the username and password.
	// This is a placeholder implementation.
	return &Token{
		Username:  "username",
		Password:  "password",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		TTL:       3600,
		RawToken:  rawToken,
	}, nil
}

// NewTokenManager creates a new TokenManager.
// It takes an IdentityProvider and TokenManagerOptions as arguments and returns a TokenManager interface.
// The IdentityProvider is used to obtain the token, and the TokenManagerOptions contains options for the TokenManager.
// The TokenManager is responsible for managing the token and refreshing it when necessary.
func NewTokenManager(idp IdentityProvider, options TokenManagerOptions) TokenManager {
	tokenParser := options.ParseToken
	if tokenParser == nil {
		tokenParser = defaultTokenParser
	}
	return &entraidTokenManager{
		idp:         idp,
		token:       nil,
		TokenParser: tokenParser,
	}
}

// entraidTokenManager is a struct that implements the TokenManager interface.
type entraidTokenManager struct {
	idp   IdentityProvider
	token *Token
	// TokenParser is a function that parses the token.
	TokenParser TokenParserFunc
}

func (e *entraidTokenManager) GetToken() (*Token, error) {
	if e.token != nil && e.token.ExpiresAt <= time.Now().Unix() {
		// copy the token so the caller can't modify it
		return copyToken(e.token), nil
	}

	rawToken := e.idp.requestToken()
	token, err := e.TokenParser(rawToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// copy the token so the caller can't modify it
	e.token = copyToken(token)
	return token, nil
}

// cancelFunc is a function that cancels the token manager.
type cancelFunc func() error

// TokenListener is a interface that contains the methods for receiving updates from the token manager.
// The token manager will call the listener's OnTokenNext method with the updated token.
// If an error occurs, the token manager will call the listener's OnTokenError method with the error.
type TokenListener interface {
	// OnTokenNext is called when the token is updated.
	OnTokenNext(token *Token)
	// OnTokenError is called when an error occurs.
	OnTokenError(err error)
}

// Start starts the token manager and returns cancelFunc to stop the token manager.
// It takes a TokenListener as an argument, which is used to receive updates.
// The token manager will call the listener's OnTokenNext method with the updated token.
// If an error occurs, the token manager will call the listener's OnError method with the error.
func (e *entraidTokenManager) Start(listener TokenListener) (cancelFunc, error) {
	// Start the token manager and return a channel that will receive updates.
	// This is a placeholder implementation.
	token, err := e.GetToken()
	if err != nil {
		return nil, fmt.Errorf("failed to start token manager: %w", err)
	}

	listener.OnTokenNext(token)

	cancel := func() error {
		// Stop the token manager.
		return nil
	}

	return cancel, nil
}
