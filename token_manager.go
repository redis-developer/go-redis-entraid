package entraid

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const MinTokenTTL = 30 * time.Minute

// TokenManagerOptions is a struct that contains the options for the TokenManager.
type TokenManagerOptions struct {
	// ExpirationRefreshRatio is the ratio of the token expiration time to refresh the token.
	// It is used to determine when to refresh the token.
	// The value should be between 0 and 1.
	// For example, if the expiration time is 1 hour and the ratio is 0.75,
	// the token will be refreshed after 45 minutes. (the token is refreshed when 75% of its lifetime has passed)
	//
	// default: 0.7
	ExpirationRefreshRatio float64

	// LowerRefreshBoundMs is the lower bound for the refresh time in milliseconds.
	// Represents the minimum time in milliseconds before token expiration to trigger a refresh, in milliseconds.
	// This value sets a fixed lower bound for when a token refresh should occur, regardless
	// of the token's total lifetime.
	//
	// default: 0 ms (no lower bound, refresh based on ExpirationRefreshRatio)
	LowerRefreshBoundMs int64

	// IdentityProviderResponseParser is a function that parses the IdentityProviderResponse.
	// The function takes the response and based on its type returns the populated Token object.
	// If this function is not provided, the default implementation will be used.
	//
	// required: true
	// default: defaultIdentityProviderResponseParser
	IdentityProviderResponseParser IdentityProviderResponseParserFunc

	// RetryOptions is a struct that contains the options for retrying the token request.
	// It contains the maximum number of attempts, initial delay, maximum delay, and backoff multiplier.
	//
	// The default values are 3 attempts, 1000 ms initial delay, 10000 ms maximum delay, and 2.0 backoff multiplier.
	RetryOptions RetryOptions
}

// RetryOptions is a struct that contains the options for retrying the token request.
type RetryOptions struct {
	// IsRetryable is a function that checks if the error is retryable.
	// It takes an error as an argument and returns a boolean value.
	//
	// default: defaultRetryableFunc
	IsRetryable func(err error) bool
	// MaxAttempts is the maximum number of attempts to retry the token request.
	//
	// default: 3
	MaxAttempts int
	// InitialDelayMs is the initial delay in milliseconds before retrying the token request.
	//
	// default: 1000 ms
	InitialDelayMs int

	// MaxDelayMs is the maximum delay in milliseconds between retry attempts.
	//
	// default: 10000 ms
	MaxDelayMs int

	// BackoffMultiplier is the multiplier for the backoff delay.
	// default: 2.0
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

// defaultIdentityProviderResponseParser is a function that parses the token and returns the username and password.
var defaultIdentityProviderResponseParser = func(response IdentityProviderResponse) (*Token, error) {
	var username, password, rawToken string
	var expiresOn time.Time
	if response == nil {
		return nil, fmt.Errorf("response is nil")
	}
	switch response.Type() {
	case ResponseTypeAuthResult:
		authResult := response.AuthResult()
		if authResult == nil {
			return nil, fmt.Errorf("auth result is nil")
		}
		rawToken = authResult.IDToken.RawToken

		username = authResult.IDToken.Oid
		password = rawToken
		expiresOn = authResult.ExpiresOn.UTC()
	case ResponseTypeRawToken, ResponseTypeAccessToken:
		token := response.RawToken()
		if response.Type() == ResponseTypeAccessToken {
			accessToken := response.AccessToken()
			if accessToken == nil {
				return nil, fmt.Errorf("access token is nil")
			}
			token = accessToken.Token
			expiresOn = accessToken.ExpiresOn.UTC()
		}

		claims := struct {
			jwt.RegisteredClaims
			Oid string `json:"oid"`
		}{}

		_, err := jwt.ParseWithClaims(token, claims, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to parse jwt token: %w", err)
		}
		rawToken = token
		username = claims.Oid
		password = rawToken

		if expiresOn.IsZero() {
			expiresOn = claims.ExpiresAt.Time
		}

	default:
		return nil, fmt.Errorf("unknown response type: %s", response.Type())
	}

	if expiresOn.IsZero() {
		return nil, fmt.Errorf("expires on is zero")
	}
	if expiresOn.Before(time.Now()) {
		return nil, fmt.Errorf("expires on is in the past")
	}
	if expiresOn.Sub(time.Now()) < MinTokenTTL {
		return nil, fmt.Errorf("expires on is less than minimum token TTL")
	}
	// parse token as jwt token and get claims

	return NewToken(
		username,
		password,
		rawToken,
		expiresOn,
		time.Now().UTC(),
		int64(expiresOn.Sub(time.Now()).Seconds()),
	), nil
}

// NewTokenManager creates a new TokenManager.
// It takes an IdentityProvider and TokenManagerOptions as arguments and returns a TokenManager interface.
// The IdentityProvider is used to obtain the token, and the TokenManagerOptions contains options for the TokenManager.
// The TokenManager is responsible for managing the token and refreshing it when necessary.
func NewTokenManager(idp IdentityProvider, options TokenManagerOptions) (TokenManager, error) {
	options = defaultTokenManagerOptionsOr(options)
	if options.ExpirationRefreshRatio <= 0 || options.ExpirationRefreshRatio > 1 {
		return nil, fmt.Errorf("expiration refresh ratio must be between 0 and 1")
	}

	if idp == nil {
		return nil, fmt.Errorf("identity provider is required")
	}

	return &entraidTokenManager{
		idp:                            idp,
		token:                          nil,
		closed:                         make(chan struct{}),
		expirationRefreshRatio:         options.ExpirationRefreshRatio,
		lowerRefreshBoundMs:            options.LowerRefreshBoundMs,
		lowerBoundDuration:             time.Duration(options.LowerRefreshBoundMs) * time.Millisecond,
		identityProviderResponseParser: options.IdentityProviderResponseParser,
		retryOptions:                   options.RetryOptions,
	}, nil
}

// entraidTokenManager is a struct that implements the TokenManager interface.
type entraidTokenManager struct {
	// idp is the identity provider used to obtain the token.
	idp IdentityProvider

	// token is the authentication token for the user which should be kept in memory if valid.
	token *Token

	// identityProviderResponseParser is a function that parses the IdentityProviderResponse.
	// it can be supplied by the user to parse the token and return the populated Token object or
	// the default implementation will be used.
	identityProviderResponseParser IdentityProviderResponseParserFunc

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

	// expirationRefreshRatio is the ratio of the token expiration time to refresh the token.
	// It is used to determine when to refresh the token.
	// The value should be between 0 and 1.
	// For example, if the expiration time is 1 hour and the ratio is 0.75,
	// the token will be refreshed after 45 minutes. (the token is refreshed when 75% of its lifetime has passed)
	expirationRefreshRatio float64

	// lowerRefreshBoundMs is the lower bound for the refresh time in milliseconds.
	// Represents the minimum time in milliseconds before token expiration to trigger a refresh, in milliseconds.
	// This value sets a fixed lower bound for when a token refresh should occur, regardless
	// of the token's total lifetime.
	lowerRefreshBoundMs int64

	// lowerBoundDuration is the lower bound for the refresh time in time.Duration.
	lowerBoundDuration time.Duration

	// closed is a channel that is closed when the token manager is closed.
	// It is used to signal the token manager to stop requesting tokens.
	closed chan struct{}
}

func (e *entraidTokenManager) GetToken() (*Token, error) {
	if e.token != nil && e.token.expiresOn.Before(time.Now().Add(e.lowerBoundDuration)) {
		// copy the token so the caller can't modify it
		return copyToken(e.token), nil
	}

	idpResult, err := e.idp.RequestToken()
	if err != nil {
		return nil, fmt.Errorf("failed to request token from idp: %w", err)
	}

	token, err := e.identityProviderResponseParser(idpResult)
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

func (e *entraidTokenManager) durationToRenewal() time.Duration {
	if e.token == nil {
		return 0
	}
	// Calculate the time to renew the token based on the expiration refresh ratio
	duration := time.Duration(float64(time.Until(e.token.expiresOn)) * e.expirationRefreshRatio)
	if duration < e.lowerBoundDuration {
		return e.lowerBoundDuration
	}

	return duration
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
			case <-e.closed:
				// Token manager is closed, stop the loop
				return
			case <-time.After(e.durationToRenewal()):
				// Token is about to expire, refresh it
				for i := 0; i < e.retryOptions.MaxAttempts; i++ {
					select {
					case <-e.closed:
						// Token manager is closed, stop the loop
						return
					default:
						// continue to next attempt
					}
					token, err := e.GetToken()
					if err == nil {
						listener.OnTokenNext(token)
						break
					}
					// check if err is retryable
					if e.retryOptions.IsRetryable(err) {
						// retryable error, continue to next attempt
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
			}
		}
	}(e.listener)

	return e.Close, nil
}

func (e *entraidTokenManager) Close() error {
	defer func() {
		if r := recover(); r != nil {
			// handle panic
			log.Printf("Recovered from panic: %v", r)
		}
	}()
	e.lock.Lock()
	defer e.lock.Unlock()
	if e.listener != nil {
		e.listener = nil
	}
	close(e.closed)
	return nil
}

// defaultRetryableFunc is a function that checks if the error is retryable.
// It takes an error as an argument and returns a boolean value.
// The function checks if the error is a net.Error and if it is a timeout or temporary error.
var defaultRetryableFunc = func(err error) bool {
	var netErr net.Error
	if err == nil {
		return true
	}

	if ok := errors.As(err, netErr); ok {
		return netErr.Timeout()
	}
	return false
}

// defaultRetryOptionsOr returns the default retry options if the provided options are not set.
// It sets the maximum number of attempts, initial delay, maximum delay, and backoff multiplier.
// The default values are 3 attempts, 1000 ms initial delay, 10000 ms maximum delay, and 2.0 backoff multiplier.
// The values can be overridden by the user.
func defaultRetryOptionsOr(retryOptions RetryOptions) RetryOptions {
	if retryOptions.IsRetryable == nil {
		retryOptions.IsRetryable = defaultRetryableFunc
	}

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

// defaultIdentityProviderResponseParserOr returns the default token parser if the provided token parser is not set.
// It sets the default token parser to the defaultIdentityProviderResponseParser function.
// The default token parser is used to parse the raw token and return a Token object.
func defaultIdentityProviderResponseParserOr(idpResponseParser IdentityProviderResponseParserFunc) IdentityProviderResponseParserFunc {
	if idpResponseParser == nil {
		return defaultIdentityProviderResponseParser
	}
	return idpResponseParser
}

func defaultTokenManagerOptionsOr(options TokenManagerOptions) TokenManagerOptions {
	options.RetryOptions = defaultRetryOptionsOr(options.RetryOptions)
	options.IdentityProviderResponseParser = defaultIdentityProviderResponseParserOr(options.IdentityProviderResponseParser)
	if options.ExpirationRefreshRatio <= 0 || options.ExpirationRefreshRatio > 1 {
		options.ExpirationRefreshRatio = 0.7
	}
	return options
}
