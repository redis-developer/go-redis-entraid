package entraid

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/stretchr/testify/assert"
)

var assertFuncNameMatches = func(t *testing.T, func1, func2 interface{}) {
	funcName1 := runtime.FuncForPC(reflect.ValueOf(func1).Pointer()).Name()
	funcName2 := runtime.FuncForPC(reflect.ValueOf(func2).Pointer()).Name()
	assert.Equal(t, funcName1, funcName2)
}

func TestTokenManager(t *testing.T) {
	t.Parallel()
	t.Run("Without IDP", func(t *testing.T) {
		tokenManager, err := NewTokenManager(nil,
			TokenManagerOptions{},
		)
		assert.Error(t, err)
		assert.Nil(t, tokenManager)
	})

	t.Run("With IDP", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{},
		)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
	})
}

func TestTokenManagerWithOptions(t *testing.T) {
	t.Parallel()
	t.Run("Bad Expiration Refresh Ration", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		options := TokenManagerOptions{
			ExpirationRefreshRatio: 5,
		}
		tokenManager, err := NewTokenManager(idp, options)
		assert.Error(t, err)
		assert.Nil(t, tokenManager)
	})
	t.Run("With IDP and Options", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		options := TokenManagerOptions{
			ExpirationRefreshRatio: 0.5,
		}
		tokenManager, err := NewTokenManager(idp, options)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		tm, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)
		assert.Equal(t, 0.5, tm.expirationRefreshRatio)
	})
	t.Run("Default Options", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		options := TokenManagerOptions{}
		tokenManager, err := NewTokenManager(idp, options)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		tm, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)
		assert.Equal(t, DefaultExpirationRefreshRatio, tm.expirationRefreshRatio)
		assert.NotNil(t, tm.retryOptions.IsRetryable)
		assertFuncNameMatches(t, tm.retryOptions.IsRetryable, defaultIsRetryable)
		assert.Equal(t, DefaultRetryOptionsMaxAttempts, tm.retryOptions.MaxAttempts)
		assert.Equal(t, DefaultRetryOptionsInitialDelayMs, tm.retryOptions.InitialDelayMs)
		assert.Equal(t, DefaultRetryOptionsMaxDelayMs, tm.retryOptions.MaxDelayMs)
		assert.Equal(t, DefaultRetryOptionsBackoffMultiplier, tm.retryOptions.BackoffMultiplier)
	})
}

func TestDefaultIdentityProviderResponseParserOr(t *testing.T) {
	t.Parallel()
	var f IdentityProviderResponseParserFunc = func(response IdentityProviderResponse) (*Token, error) {
		return nil, nil
	}

	result := defaultIdentityProviderResponseParserOr(f)
	assert.NotNil(t, result)
	assertFuncNameMatches(t, result, f)

	defaultFunc := defaultIdentityProviderResponseParserOr(nil)
	assert.NotNil(t, defaultFunc)
	assertFuncNameMatches(t, defaultFunc, defaultIdentityProviderResponseParser)
}

func TestDefaultIsRetryable(t *testing.T) {
	t.Parallel()
	// with network error timeout
	t.Run("Non-Retryable Error", func(t *testing.T) {
		err := &azcore.ResponseError{
			StatusCode: 500,
		}
		is := defaultIsRetryable(err)
		assert.False(t, is)
	})

	t.Run("Nil Error", func(t *testing.T) {
		var err error
		is := defaultIsRetryable(err)
		assert.True(t, is)

		is = defaultIsRetryable(nil)
		assert.True(t, is)
	})

	t.Run("Retryable Error with Timeout", func(t *testing.T) {
		err := &mockError{isTimeout: true}
		result := defaultIsRetryable(err)
		assert.True(t, result)
	})
	t.Run("Retryable Error with Temporary", func(t *testing.T) {
		err := &mockError{isTemporary: true}
		result := defaultIsRetryable(err)
		assert.True(t, result)
	})

	t.Run("Retryable Error with err parent of os.ErrDeadlineExceeded", func(t *testing.T) {
		err := fmt.Errorf("timeout: %w", os.ErrDeadlineExceeded)
		res := defaultIsRetryable(err)
		assert.True(t, res)
	})
}
