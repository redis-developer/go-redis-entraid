package entraid

import (
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

func TestTokenManager_Close(t *testing.T) {
	t.Parallel()
	t.Run("Close", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		listener := &mockTokenListener{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{
				IdentityProviderResponseParser: mockTokenParserFunc,
			},
		)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		tm, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)
		assert.Nil(t, tm.listener)
		assert.NotPanics(t, func() {
			err = tokenManager.Close()
			assert.Error(t, err)
		})
		rawResponse, err := NewIDPResponse(ResponseTypeRawToken, "test")
		assert.NoError(t, err)

		idp.On("RequestToken").Return(rawResponse, nil)
		listener.On("OnTokenNext", mock.AnythingOfType("*entraid.Token")).Return()

		assert.NotPanics(t, func() {
			cancel, err := tokenManager.Start(listener)
			assert.NotNil(t, cancel)
			assert.NoError(t, err)
		})
		assert.NotNil(t, tm.listener)

		err = tokenManager.Close()
		assert.Nil(t, tm.listener)
		assert.NoError(t, err)

		assert.NotPanics(t, func() {
			err = tokenManager.Close()
			assert.Error(t, err)
		})
	})

	t.Run("Close with Cancel", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		listener := &mockTokenListener{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{
				IdentityProviderResponseParser: mockTokenParserFunc,
			},
		)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		tm, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)
		assert.Nil(t, tm.listener)

		rawResponse, err := NewIDPResponse(ResponseTypeRawToken, "test")
		assert.NoError(t, err)

		idp.On("RequestToken").Return(rawResponse, nil)
		listener.On("OnTokenNext", mock.AnythingOfType("*entraid.Token")).Return()

		assert.NotPanics(t, func() {
			cancel, err := tokenManager.Start(listener)
			assert.NotNil(t, cancel)
			assert.NoError(t, err)
			assert.NotNil(t, tm.listener)
			err = cancel()
			assert.NoError(t, err)
			assert.Nil(t, tm.listener)
			err = cancel()
			assert.Error(t, err)
			assert.Nil(t, tm.listener)
		})
	})
	t.Run("Close in multiple threads", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		listener := &mockTokenListener{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{
				IdentityProviderResponseParser: mockTokenParserFunc,
			},
		)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		tm, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)
		assert.Nil(t, tm.listener)

		rawResponse, err := NewIDPResponse(ResponseTypeRawToken, "test")
		assert.NoError(t, err)

		idp.On("RequestToken").Return(rawResponse, nil)
		listener.On("OnTokenNext", mock.AnythingOfType("*entraid.Token")).Return()

		assert.NotPanics(t, func() {
			cancel, err := tokenManager.Start(listener)
			assert.NotNil(t, cancel)
			assert.NoError(t, err)
			assert.NotNil(t, tm.listener)
			var hasStopped int
			var alreadyStopped int32
			wg := &sync.WaitGroup{}

			// Start 500000 goroutines to close the token manager
			// and check if the listener is nil after each close.
			numExecutions := 500000
			for i := 0; i < numExecutions; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					time.Sleep(time.Duration(int64(rand.Intn(100)) * int64(time.Millisecond)))
					err = tokenManager.Close()
					if err == nil {
						hasStopped += 1
						return
					} else {
						atomic.AddInt32(&alreadyStopped, 1)
					}
					assert.Nil(t, tm.listener)
					assert.Error(t, err)
				}()
			}
			wg.Wait()
			assert.Nil(t, tm.listener)
			assert.Equal(t, 1, hasStopped)
			assert.Equal(t, int32(numExecutions-1), atomic.LoadInt32(&alreadyStopped))
		})
	})
}

func TestTokenManager_Start(t *testing.T) {
	t.Parallel()
	t.Run("Start in multiple threads", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		listener := &mockTokenListener{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{
				IdentityProviderResponseParser: mockTokenParserFunc,
			},
		)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		tm, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)
		assert.Nil(t, tm.listener)

		rawResponse, err := NewIDPResponse(ResponseTypeRawToken, "test")
		assert.NoError(t, err)

		idp.On("RequestToken").Return(rawResponse, nil)
		listener.On("OnTokenNext", mock.AnythingOfType("*entraid.Token")).Return()

		assert.NotPanics(t, func() {
			var hasStarted int
			var alreadyStarted int32
			wg := &sync.WaitGroup{}

			numExecutions := 500000
			for i := 0; i < numExecutions; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					time.Sleep(time.Duration(int64(rand.Intn(100)) * int64(time.Millisecond)))
					_, err = tokenManager.Start(listener)
					if err == nil {
						hasStarted += 1
						return
					} else {
						atomic.AddInt32(&alreadyStarted, 1)
					}
					assert.NotNil(t, tm.listener)
					assert.Error(t, err)
				}()
			}
			wg.Wait()
			assert.NotNil(t, tm.listener)
			assert.Equal(t, 1, hasStarted)
			assert.Equal(t, int32(numExecutions-1), atomic.LoadInt32(&alreadyStarted))
			cancel, err := tokenManager.Start(listener)
			assert.Nil(t, cancel)
			assert.Error(t, err)
			assert.NotNil(t, tm.listener)
		})
	})

	t.Run("concurrent stress token manager", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		listener := &mockTokenListener{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{
				IdentityProviderResponseParser: mockTokenParserFunc,
			},
		)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		tm, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)
		assert.Nil(t, tm.listener)

		rawResponse, err := NewIDPResponse(ResponseTypeRawToken, "test")
		assert.NoError(t, err)

		assert.NotPanics(t, func() {
			var last int32
			wg := &sync.WaitGroup{}

			numExecutions := 50000
			for i := 0; i < numExecutions; i++ {
				wg.Add(1)
				go func(num int) {
					defer wg.Done()
					time.Sleep(time.Duration(int64(rand.Intn(1000)) * int64(time.Millisecond)))
					if num%2 == 0 {
						_ = tokenManager.Close()
					} else {
						idp.On("RequestToken").Return(rawResponse, nil)
						listener.On("OnTokenNext", mock.AnythingOfType("*entraid.Token")).Return()
						_, _ = tokenManager.Start(listener)
					}
					atomic.StoreInt32(&last, int32(num))
				}(i)
			}
			wg.Wait()
			lastExecution := atomic.LoadInt32(&last)
			if lastExecution%2 == 0 {
				assert.Nil(t, tm.listener)
			} else {
				assert.NotNil(t, tm.listener)
				cancel, err := tokenManager.Start(listener)
				assert.Nil(t, cancel)
				assert.Error(t, err)
				// Close the token manager
				err = tokenManager.Close()
				assert.Nil(t, err)
			}
			assert.Nil(t, tm.listener)
		})
	})
}

func TestDefaultIdentityProviderResponseParser(t *testing.T) {
	t.Parallel()
	t.Run("Default IdentityProviderResponseParser with type AuthResult", func(t *testing.T) {
		idpResponse, err := NewIDPResponse(ResponseTypeAuthResult,
			&public.AuthResult{
				ExpiresOn: time.Now().Add(time.Hour),
			})
		assert.NoError(t, err)
		token, err := defaultIdentityProviderResponseParser(idpResponse)
		assert.NoError(t, err)
		assert.NotNil(t, token)
	})
	t.Run("Default IdentityProviderResponseParser with type AccessToken", func(t *testing.T) {
		idpResponse, err := NewIDPResponse(ResponseTypeAccessToken, &azcore.AccessToken{
			Token:     testJWTtoken,
			ExpiresOn: time.Now().Add(time.Hour),
		})
		assert.NoError(t, err)
		token, err := defaultIdentityProviderResponseParser(idpResponse)
		assert.NoError(t, err)
		assert.NotNil(t, token)
	})
	t.Run("Default IdentityProviderResponseParser with type RawToken", func(t *testing.T) {
		idpResponse, err := NewIDPResponse(ResponseTypeRawToken, testJWTtoken)
		assert.NoError(t, err)
		token, err := defaultIdentityProviderResponseParser(idpResponse)
		assert.NoError(t, err)
		assert.NotNil(t, token)
	})

	t.Run("NewIDPResponse with type Unknown", func(t *testing.T) {
		idpResponse, err := NewIDPResponse("Unknown", testJWTtoken)
		assert.Error(t, err)
		assert.Nil(t, idpResponse)
	})

	t.Run("NewIDPResponse with type and nil value", func(t *testing.T) {
		idpResponse, err := NewIDPResponse(ResponseTypeRawToken, nil)
		assert.Error(t, err)
		assert.Nil(t, idpResponse)
		idpResponse, err = NewIDPResponse(ResponseTypeAuthResult, nil)
		assert.Error(t, err)
		assert.Nil(t, idpResponse)
		idpResponse, err = NewIDPResponse(ResponseTypeAccessToken, nil)
		assert.Error(t, err)
		assert.Nil(t, idpResponse)
	})
	t.Run("Default IdentityProviderResponseParser with type Unknown", func(t *testing.T) {
		resp := &authResult{
			resultType: "Unknown",
		}
		token, err := defaultIdentityProviderResponseParser(resp)
		assert.Error(t, err)
		assert.Nil(t, token)
	})
	types := []string{
		ResponseTypeAuthResult,
		ResponseTypeAccessToken,
		ResponseTypeRawToken,
	}
	for _, rt := range types {
		t.Run(fmt.Sprintf("Default IdentityProviderResponseParser with response type %s and nil value", rt), func(t *testing.T) {
			resp := &authResult{
				resultType: rt,
			}
			token, err := defaultIdentityProviderResponseParser(resp)
			assert.Error(t, err)
			assert.Nil(t, token)
		})
	}

	t.Run("Default IdentityProviderResponseParser with response nil", func(t *testing.T) {
		token, err := defaultIdentityProviderResponseParser(nil)
		assert.Error(t, err)
		assert.Nil(t, token)
	})
}
