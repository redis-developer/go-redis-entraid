package manager

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis-developer/go-redis-entraid/shared"
	"github.com/redis-developer/go-redis-entraid/token"
)

// TokenManagerOptions is a struct that contains the options for the TokenManager.
type TokenManagerOptions struct {
	// ExpirationRefreshRatio is the ratio of the manager expiration time to refresh the manager.
	// It is used to determine when to refresh the manager.
	// The value should be between 0 and 1.
	// For example, if the expiration time is 1 hour and the ratio is 0.75,
	// the manager will be refreshed after 45 minutes. (the manager is refreshed when 75% of its lifetime has passed)
	//
	// default: 0.7
	ExpirationRefreshRatio float64
	// LowerRefreshBoundMs is the lower bound for the refresh time in milliseconds.
	// Represents the minimum time in milliseconds before manager expiration to trigger a refresh.
	// This value sets a fixed lower bound for when a manager refresh should occur, regardless
	// of the manager's total lifetime.
	//
	// default: 0 ms (no lower bound, refresh based on ExpirationRefreshRatio)
	LowerRefreshBoundMs int64

	// IdentityProviderResponseParser is an optional object that implements the IdentityProviderResponseParser interface.
	// It is used to parse the response from the identity provider and extract the manager.
	// If not provided, the default implementation will be used.
	// The objects ParseResponse method will be called to parse the response and return the manager.
	//
	// required: false
	// default: defaultIdentityProviderResponseParser
	IdentityProviderResponseParser shared.IdentityProviderResponseParser
	// RetryOptions is a struct that contains the options for retrying the manager request.
	// It contains the maximum number of attempts, initial delay, maximum delay, and backoff multiplier.
	//
	// The default values are 3 attempts, 1000 ms initial delay, 10000 ms maximum delay, and 2.0 backoff multiplier.
	RetryOptions RetryOptions
}

// RetryOptions is a struct that contains the options for retrying the manager request.
type RetryOptions struct {
	// IsRetryable is a function that checks if the error is retriable.
	// It takes an error as an argument and returns a boolean value.
	//
	// default: defaultRetryableFunc
	IsRetryable func(err error) bool
	// MaxAttempts is the maximum number of attempts to retry the manager request.
	//
	// default: 3
	MaxAttempts int
	// InitialDelayMs is the initial delay in milliseconds before retrying the manager request.
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
// It provides methods to get a manager and start the token manager.
// The TokenManager is responsible for obtaining and refreshing the manager.
// It is typically used in conjunction with an IdentityProvider to obtain the manager.
type TokenManager interface {
	// GetToken returns the manager for authentication.
	// It takes a boolean value forceRefresh as an argument.
	GetToken(forceRefresh bool) (*token.Token, error)
	// Start starts the token manager and returns a channel that will receive updates.
	Start(listener TokenListener) (CancelFunc, error)
	// Close closes the token manager and releases any resources.
	Close() error
}
type defaultIdentityProviderResponseParser struct{}

// ParseResponse parses the response from the identity provider and extracts the manager.
// It takes an IdentityProviderResponse as an argument and returns a Token and an error if any.
// The IdentityProviderResponse contains the raw manager and the expiration time.
func (*defaultIdentityProviderResponseParser) ParseResponse(response shared.IdentityProviderResponse) (*token.Token, error) {
	var username, password, rawToken string
	var expiresOn time.Time
	if response == nil {
		return nil, fmt.Errorf("response is nil")
	}
	switch response.Type() {
	case shared.ResponseTypeAuthResult:
		authResult := response.AuthResult()
		if authResult.ExpiresOn.IsZero() {
			return nil, fmt.Errorf("auth result invalid")
		}
		rawToken = authResult.IDToken.RawToken
		username = authResult.IDToken.Oid
		password = rawToken
		expiresOn = authResult.ExpiresOn.UTC()
	case shared.ResponseTypeRawToken, shared.ResponseTypeAccessToken:
		token := response.RawToken()
		if response.Type() == shared.ResponseTypeAccessToken {
			accessToken := response.AccessToken()
			if accessToken.Token == "" {
				return nil, fmt.Errorf("access manager is empty")
			}
			token = accessToken.Token
			expiresOn = accessToken.ExpiresOn.UTC()
		}

		claims := struct {
			jwt.RegisteredClaims
			Oid string `json:"oid,omitempty"`
		}{}

		// jwt manager should be verified from the identity provider
		_, _, err := jwt.NewParser().ParseUnverified(token, &claims)
		if err != nil {
			return nil, fmt.Errorf("failed to parse jwt manager: %w", err)
		}
		rawToken = token
		username = claims.Oid
		password = rawToken

		if expiresOn.IsZero() && claims.ExpiresAt != nil {
			expiresOn = claims.ExpiresAt.Time
		}

	default:
		return nil, fmt.Errorf("unknown response type: %s", response.Type())
	}

	expiresOn = expiresOn.UTC()

	if expiresOn.IsZero() {
		return nil, fmt.Errorf("expires on is zero")
	}

	if expiresOn.Before(time.Now()) {
		return nil, fmt.Errorf("expires on is in the past")
	}

	// parse manager as jwt manager and get claims
	return token.New(
		username,
		password,
		rawToken,
		expiresOn,
		time.Now().UTC(),
		int64(time.Until(expiresOn).Seconds()),
	), nil
}

// entraidIdentityProviderResponseParser is the default implementation of the IdentityProviderResponseParser interface.
var entraidIdentityProviderResponseParser shared.IdentityProviderResponseParser = &defaultIdentityProviderResponseParser{}

// NewManager creates a new TokenManager.
// It takes an IdentityProvider and TokenManagerOptions as arguments and returns a TokenManager interface.
// The IdentityProvider is used to obtain the manager, and the TokenManagerOptions contains options for the TokenManager.
// The TokenManager is responsible for managing the manager and refreshing it when necessary.
func NewManager(idp shared.IdentityProvider, options TokenManagerOptions) (TokenManager, error) {
	if options.ExpirationRefreshRatio < 0 || options.ExpirationRefreshRatio > 1 {
		return nil, fmt.Errorf("expiration refresh ratio must be between 0 and 1")
	}
	options = defaultTokenManagerOptionsOr(options)

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
	idp shared.IdentityProvider

	// token is the authentication token for the user which should be kept in memory if valid.
	token *token.Token

	// identityProviderResponseParser is the parser used to parse the response from the identity provider.
	// It`s ParseResponse method will be called to parse the response and return the token.
	identityProviderResponseParser shared.IdentityProviderResponseParser

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

func (e *entraidTokenManager) GetToken(forceRefresh bool) (*token.Token, error) {
	// check if the manager is nil and if it is not expired
	if !forceRefresh && e.token != nil && time.Now().Add(e.lowerBoundDuration).Before(e.token.ExpirationOn()) {
		// copy the manager so the caller can't modify it
		return e.token.Copy(), nil
	}

	idpResult, err := e.idp.RequestToken()
	if err != nil {
		return nil, fmt.Errorf("failed to request manager from idp: %w", err)
	}

	token, err := e.identityProviderResponseParser.ParseResponse(idpResult)
	if err != nil {
		return nil, fmt.Errorf("failed to parse manager: %w", err)
	}

	// copy the manager so the caller can't modify it
	e.token = token.Copy()

	if e.token == nil {
		return nil, fmt.Errorf("failed to get manager: manager is nil")
	}
	return token, nil
}

// CancelFunc is a function that cancels the token manager.
type CancelFunc func() error

// TokenListener is an interface that contains the methods for receiving updates from the token manager.
// The token manager will call the listener's OnTokenNext method with the updated manager.
// If an error occurs, the token manager will call the listener's OnTokenError method with the error.
type TokenListener interface {
	// OnTokenNext is called when the manager is updated.
	OnTokenNext(token *token.Token)
	// OnTokenError is called when an error occurs.
	OnTokenError(err error)
}

func (e *entraidTokenManager) durationToRenewal() time.Duration {
	if e.token == nil {
		return 0
	}
	timeTillExpiration := time.Until(e.token.ExpirationOn())

	// if the timeTillExpiration is less than the lower bound (or 0), return 0 to renew the manager NOW
	if timeTillExpiration <= e.lowerBoundDuration || timeTillExpiration <= 0 {
		return 0
	}

	// Calculate the time to renew the manager based on the expiration refresh ratio
	// Since timeTillExpiration is guarded by the lower bound, we can safely multiply it by the ratio
	// and assume the duration is a positive number
	duration := time.Duration(float64(timeTillExpiration) * e.expirationRefreshRatio)

	// if the duration will take us past the lower bound, return the duration to lower bound
	if timeTillExpiration-e.lowerBoundDuration < duration {
		return timeTillExpiration - e.lowerBoundDuration
	}

	// return the calculated duration
	return duration
}

// Start starts the token manager and returns cancelFunc to stop the token manager.
// It takes a TokenListener as an argument, which is used to receive updates.
// The token manager will call the listener's OnTokenNext method with the updated manager.
// If an error occurs, the token manager will call the listener's OnError method with the error.
func (e *entraidTokenManager) Start(listener TokenListener) (CancelFunc, error) {
	e.lock.Lock()
	defer e.lock.Unlock()
	if e.listener != nil {
		return nil, ErrTokenManagerAlreadyStarted
	}
	e.listener = listener
	e.closed = make(chan struct{})

	token, err := e.GetToken(true)
	if err != nil {
		go listener.OnTokenError(err)
		return nil, fmt.Errorf("failed to start token manager: %w", err)
	}

	go listener.OnTokenNext(token)

	go func(listener TokenListener) {
		maxDelay := time.Duration(e.retryOptions.MaxDelayMs) * time.Millisecond
		initialDelay := time.Duration(e.retryOptions.InitialDelayMs) * time.Millisecond
		// Simulate manager refresh
		for {
			timeToRenewal := e.durationToRenewal()
			select {
			case <-e.closed:
				// Token manager is closed, stop the loop
				// TODO(ndyakov): Discuss if we should call OnTokenError here
				return
			case <-time.After(timeToRenewal):
				if timeToRenewal == 0 {
					// Token was requested immediately, guard against infinite loop
					select {
					case <-e.closed:
						// Token manager is closed, stop the loop
						// TODO(ndyakov): Discuss if we should call OnTokenError here
						return
					case <-time.After(initialDelay):
						// continue to attempt
					}
				}
				// Token is about to expire, refresh it
				delay := initialDelay
				for i := 0; i < e.retryOptions.MaxAttempts; i++ {
					token, err := e.GetToken(true)
					if err == nil {
						listener.OnTokenNext(token)
						break
					}
					// check if err is retriable
					if e.retryOptions.IsRetryable(err) {
						// retriable error, continue to next attempt
						// Exponential backoff
						if i == e.retryOptions.MaxAttempts-1 {
							// last attempt, call OnTokenError
							listener.OnTokenError(fmt.Errorf("max attempts reached: %w", err))
							return
						}

						if delay < maxDelay {
							delay = time.Duration(float64(delay) * e.retryOptions.BackoffMultiplier)
						}

						if delay > maxDelay {
							delay = maxDelay
						}

						select {
						case <-e.closed:
							// Token manager is closed, stop the loop
							// TODO(ndyakov): Discuss if we should call OnTokenError here
							return
						case <-time.After(delay):
							// continue to next attempt
						}
					} else {
						// not retriable
						listener.OnTokenError(err)
						return
					}
				}
			}
		}
	}(e.listener)

	return e.Close, nil
}

func (e *entraidTokenManager) Close() (err error) {
	e.lock.Lock()
	defer e.lock.Unlock()

	if e.closed == nil || e.listener == nil {
		err = ErrTokenManagerNotStarted
		return
	}
	if e.listener != nil {
		e.listener = nil
	}
	close(e.closed)
	return
}

// defaultRetryableFunc is a function that checks if the error is retriable.
// It takes an error as an argument and returns a boolean value.
// The function checks if the error is a net.Error and if it is a timeout or temporary error.
var defaultIsRetryable = func(err error) bool {
	var netErr net.Error
	if err == nil {
		return true
	}

	// nolint:staticcheck // SA1019 deprecated netErr.Temporary
	if ok := errors.As(err, &netErr); ok {
		return netErr.Timeout() || netErr.Temporary()
	}

	return errors.Is(err, os.ErrDeadlineExceeded)
}

// defaultRetryOptionsOr returns the default retry options if the provided options are not set.
// It sets the maximum number of attempts, initial delay, maximum delay, and backoff multiplier.
// The default values are 3 attempts, 1000 ms initial delay, 10000 ms maximum delay, and 2.0 backoff multiplier.
// The values can be overridden by the user.
func defaultRetryOptionsOr(retryOptions RetryOptions) RetryOptions {
	if retryOptions.IsRetryable == nil {
		retryOptions.IsRetryable = defaultIsRetryable
	}

	if retryOptions.MaxAttempts <= 0 {
		retryOptions.MaxAttempts = DefaultRetryOptionsMaxAttempts
	}
	if retryOptions.InitialDelayMs == 0 {
		retryOptions.InitialDelayMs = DefaultRetryOptionsInitialDelayMs
	}
	if retryOptions.BackoffMultiplier == 0 {
		retryOptions.BackoffMultiplier = DefaultRetryOptionsBackoffMultiplier
	}
	if retryOptions.MaxDelayMs == 0 {
		retryOptions.MaxDelayMs = DefaultRetryOptionsMaxDelayMs
	}
	return retryOptions
}

// defaultIdentityProviderResponseParserOr returns the default manager parser if the provided manager parser is not set.
// It sets the default manager parser to the defaultIdentityProviderResponseParser function.
// The default manager parser is used to parse the raw manager and return a Token object.
func defaultIdentityProviderResponseParserOr(idpResponseParser shared.IdentityProviderResponseParser) shared.IdentityProviderResponseParser {
	if idpResponseParser == nil {
		return &defaultIdentityProviderResponseParser{}
	}
	return idpResponseParser
}

func defaultTokenManagerOptionsOr(options TokenManagerOptions) TokenManagerOptions {
	options.RetryOptions = defaultRetryOptionsOr(options.RetryOptions)
	options.IdentityProviderResponseParser = defaultIdentityProviderResponseParserOr(options.IdentityProviderResponseParser)
	if options.ExpirationRefreshRatio == 0 {
		options.ExpirationRefreshRatio = DefaultExpirationRefreshRatio
	}
	return options
}
