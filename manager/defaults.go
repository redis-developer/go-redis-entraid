package manager

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis-developer/go-redis-entraid/shared"
	"github.com/redis-developer/go-redis-entraid/token"
)

const (
	DefaultExpirationRefreshRatio        = 0.7
	DefaultRetryOptionsMaxAttempts       = 3
	DefaultRetryOptionsInitialDelayMs    = 1000
	DefaultRetryOptionsBackoffMultiplier = 2.0
	DefaultRetryOptionsMaxDelayMs        = 10000
)

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

// defaultIdentityProviderResponseParserOr returns the default token parser if the provided token parser is not set.
// It sets the default token parser to the defaultIdentityProviderResponseParser function.
// The default token parser is used to parse the raw token and return a Token object.
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

type defaultIdentityProviderResponseParser struct{}

// ParseResponse parses the response from the identity provider and extracts the token.
// It takes an IdentityProviderResponse as an argument and returns a Token and an error if any.
// The IdentityProviderResponse contains the raw token and the expiration time.
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
				return nil, fmt.Errorf("access token is empty")
			}
			token = accessToken.Token
			expiresOn = accessToken.ExpiresOn.UTC()
		}

		claims := struct {
			jwt.RegisteredClaims
			Oid string `json:"oid,omitempty"`
		}{}

		// jwt token should be verified from the identity provider
		_, _, err := jwt.NewParser().ParseUnverified(token, &claims)
		if err != nil {
			return nil, fmt.Errorf("failed to parse jwt token: %w", err)
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

	// parse token as jwt token and get claims
	return token.New(
		username,
		password,
		rawToken,
		expiresOn,
		time.Now().UTC(),
		int64(time.Until(expiresOn).Seconds()),
	), nil
}
