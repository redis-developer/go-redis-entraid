package entraid

import (
	"fmt"
	"sync"
	"time"
)

const MinTokenTTL = 30 * time.Minute

// TokenManagerOptions is a struct that contains the options for the TokenManager.
type TokenManagerOptions struct {
	// ExpirationRefreshRatio is the ratio of the token expiration time to refresh the token.
	// It is used to determine when to refresh the token.
	// The value should be between 0 and 1.
	// For example, if the expiration time is 1 hour and the ratio is 0.5,
	// the token will be refreshed after 30 minutes.
	ExpirationRefreshRatio float64

	// TokenParser is a function that parses the raw token and returns a Token object.
	// The function takes the raw token as a string and returns a Token object and an error.
	// If this function is not provided, the default implementation will be used.
	TokenParser TokenParserFunc

	// RetryOptions is a struct that contains the options for retrying the token request.
	// It contains the maximum number of attempts, initial delay, maximum delay, and backoff multiplier.
	RetryOptions RetryOptions
}

// RetryOptions is a struct that contains the options for retrying the token request.
type RetryOptions struct {
	// MaxAttempts is the maximum number of attempts to retry the token request.
	MaxAttempts int
	// InitialDelayMs is the initial delay in milliseconds before retrying the token request.
	InitialDelayMs int
	// MaxDelayMs is the maximum delay in milliseconds between retry attempts.
	MaxDelayMs int
	// BackoffMultiplier is the multiplier for the backoff delay.
	BackoffMultiplier float64
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
	// Close closes the token manager and releases any resources.
	Close() error
}

// defaultTokenParser is a function that parses the raw token and returns Token object.
var defaultTokenParser = func(rawToken string, expiresOn time.Time) (*Token, error) {
	// Parse the token and return the username and password.
	// This is a placeholder implementation.
	return &Token{
		Username:  "username",
		Password:  "password",
		ExpiresOn: expiresOn,
		TTL:       expiresOn.Unix() - time.Now().Unix(),
		RawToken:  rawToken,
	}, nil
}

// NewTokenManager creates a new TokenManager.
// It takes an IdentityProvider and TokenManagerOptions as arguments and returns a TokenManager interface.
// The IdentityProvider is used to obtain the token, and the TokenManagerOptions contains options for the TokenManager.
// The TokenManager is responsible for managing the token and refreshing it when necessary.
func NewTokenManager(idp IdentityProvider, options TokenManagerOptions) (TokenManager, error) {
	tokenParser := defaultTokenParserOr(options.TokenParser)
	retryOptions := defaultRetryOptionsOr(options.RetryOptions)
	if idp == nil {
		return nil, fmt.Errorf("identity provider is required")
	}

	return &entraidTokenManager{
		idp:          idp,
		token:        nil,
		closed:       make(chan struct{}),
		tokenParser:  tokenParser,
		retryOptions: retryOptions,
	}, nil
}

// entraidTokenManager is a struct that implements the TokenManager interface.
type entraidTokenManager struct {
	idp   IdentityProvider
	token *Token
	// TokenParser is a function that parses the token.
	tokenParser TokenParserFunc

	// retryOptions is a struct that contains the options for retrying the token request.
	// It contains the maximum number of attempts, initial delay, maximum delay, and backoff multiplier.
	// The default values are 3 attempts, 1000 ms initial delay, 10000 ms maximum delay, and 2.0 backoff multiplier.
	// The values can be overridden by the user.
	retryOptions RetryOptions

	// listener is the single listener for the token manager.
	// It is used to receive updates from the token manager.
	// The token manager will call the listener's OnTokenNext method with the updated token.
	// If an error occurs, the token manager will call the listener's OnTokenError method with the error.
	// if listener is set, Start will fail
	listener TokenListener

	// lock locks the listener to prevent concurrent access.
	lock sync.Mutex

	closed chan struct{}
}

func (e *entraidTokenManager) GetToken() (*Token, error) {
	if e.token != nil && e.token.ExpiresOn.After(time.Now().Add(MinTokenTTL)) {
		// copy the token so the caller can't modify it
		return copyToken(e.token), nil
	}

	rawToken, expiresOn, err := e.idp.RequestToken()
	if err != nil {
		return nil, fmt.Errorf("failed to request token: %w", err)
	}

	token, err := e.tokenParser(rawToken, expiresOn)
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
	e.lock.Lock()
	defer e.lock.Unlock()
	if e.listener != nil {
		return nil, fmt.Errorf("token manager already started")
	}
	e.listener = listener
	e.closed = make(chan struct{})

	token, err := e.GetToken()
	if err != nil {
		return nil, fmt.Errorf("failed to start token manager: %w", err)
	}

	go listener.OnTokenNext(token)

	go func(listener TokenListener) {
		// Simulate token refresh
		for {
			select {
			case <-time.After(time.Duration(e.token.TTL) * time.Second):
				// Token is about to expire, refresh it
				for i := 0; i < e.retryOptions.MaxAttempts; i++ {
					token, err := e.GetToken()
					if err == nil {
						listener.OnTokenNext(token)
						break
					}
					// check if err is retryable
					if err.Error() == "retryable error" {
						// retry
						continue
					} else {
						// not retryable
						listener.OnTokenError(err)
						return
					}

					// check if max attempts reached
					if i == e.retryOptions.MaxAttempts-1 {
						listener.OnTokenError(err)
						return
					}

					// Exponential backoff
					delay := time.Duration(e.retryOptions.InitialDelayMs) * time.Millisecond
					if delay < time.Duration(e.retryOptions.MaxDelayMs)*time.Millisecond {
						delay = time.Duration(float64(delay) * e.retryOptions.BackoffMultiplier)
					}

					time.Sleep(delay)

					if delay > time.Duration(e.retryOptions.MaxDelayMs)*time.Millisecond {
						delay = time.Duration(e.retryOptions.MaxDelayMs) * time.Millisecond
					}
				}
			case <-e.closed:
				// Token manager is closed, stop the loop
				return
			}
		}
	}(e.listener)

	return e.Close, nil
}

func (e *entraidTokenManager) Close() error {
	e.lock.Lock()
	defer e.lock.Unlock()
	if e.listener != nil {
		e.listener = nil
	}
	close(e.closed)
	return nil
}

// defaultRetryOptionsOr returns the default retry options if the provided options are not set.
// It sets the maximum number of attempts, initial delay, maximum delay, and backoff multiplier.
// The default values are 3 attempts, 1000 ms initial delay, 10000 ms maximum delay, and 2.0 backoff multiplier.
// The values can be overridden by the user.
func defaultRetryOptionsOr(retryOptions RetryOptions) RetryOptions {
	if retryOptions.MaxAttempts <= 0 {
		retryOptions.MaxAttempts = 3
	}
	if retryOptions.InitialDelayMs == 0 {
		retryOptions.InitialDelayMs = 1000
	}
	if retryOptions.BackoffMultiplier == 0 {
		retryOptions.BackoffMultiplier = 2.0
	}
	if retryOptions.MaxDelayMs == 0 {
		retryOptions.MaxDelayMs = 10000
	}
	return retryOptions
}

// defaultTokenParserOr returns the default token parser if the provided token parser is not set.
// It sets the default token parser to the defaultTokenParser function.
// The default token parser is used to parse the raw token and return a Token object.
func defaultTokenParserOr(tokenParser TokenParserFunc) TokenParserFunc {
	if tokenParser == nil {
		return defaultTokenParser
	}
	return tokenParser
}
