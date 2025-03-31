package entraid

import (
	"reflect"
	"runtime"
	"testing"

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
		assertFuncNameMatches(t, tm.retryOptions.IsRetryable, defaultRetryableFunc)
		assert.Equal(t, DefaultRetryOptionsMaxAttempts, tm.retryOptions.MaxAttempts)
		assert.Equal(t, DefaultRetryOptionsInitialDelayMs, tm.retryOptions.InitialDelayMs)
		assert.Equal(t, DefaultRetryOptionsMaxDelayMs, tm.retryOptions.MaxDelayMs)
		assert.Equal(t, DefaultRetryOptionsBackoffMultiplier, tm.retryOptions.BackoffMultiplier)

	})
}
