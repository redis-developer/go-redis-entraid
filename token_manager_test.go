package entraid

import (
	"fmt"
	"log"
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
	var f IdentityProviderResponseParser = &mockIdentityProviderResponseParser{}

	result := defaultIdentityProviderResponseParserOr(f)
	assert.NotNil(t, result)
	assert.Equal(t, result, f)

	defaultParser := defaultIdentityProviderResponseParserOr(nil)
	assert.NotNil(t, defaultParser)
	assert.NotEqual(t, defaultParser, f)
	assert.Equal(t, entraidIdentityProviderResponseParser, defaultParser)
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
		mParser := &mockIdentityProviderResponseParser{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{
				IdentityProviderResponseParser: mParser,
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
		mParser.On("ParseResponse", rawResponse).Return(testTokenValid, nil)
		listener.On("OnTokenNext", testTokenValid).Return()

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
		mParser := &mockIdentityProviderResponseParser{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{
				IdentityProviderResponseParser: mParser,
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
		mParser.On("ParseResponse", rawResponse).Return(testTokenValid, nil)
		listener.On("OnTokenNext", testTokenValid).Return()

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
		mParser := &mockIdentityProviderResponseParser{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{
				IdentityProviderResponseParser: mParser,
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
		mParser.On("ParseResponse", rawResponse).Return(testTokenValid, nil)
		listener.On("OnTokenNext", testTokenValid).Return()

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
		mParser := &mockIdentityProviderResponseParser{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{
				IdentityProviderResponseParser: mParser,
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
		mParser.On("ParseResponse", rawResponse).Return(testTokenValid, nil)
		listener.On("OnTokenNext", testTokenValid).Return()

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
					_, err := tokenManager.Start(listener)
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
		mParser := &mockIdentityProviderResponseParser{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{
				IdentityProviderResponseParser: mParser,
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
						mParser.On("ParseResponse", rawResponse).Return(testTokenValid, nil)
						listener.On("OnTokenNext", testTokenValid).Return()
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
	parser := &defaultIdentityProviderResponseParser{}
	t.Run("Default IdentityProviderResponseParser with type AuthResult", func(t *testing.T) {
		authResult := &public.AuthResult{
			ExpiresOn: time.Now().Add(time.Hour).UTC(),
		}
		idpResponse, err := NewIDPResponse(ResponseTypeAuthResult,
			authResult)
		assert.NoError(t, err)
		token, err := parser.ParseResponse(idpResponse)
		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.Equal(t, authResult.ExpiresOn, token.ExpirationOn())
	})
	t.Run("Default IdentityProviderResponseParser with type AccessToken", func(t *testing.T) {
		accessToken := &azcore.AccessToken{
			Token:     testJWTtoken,
			ExpiresOn: time.Now().Add(time.Hour).UTC(),
		}
		idpResponse, err := NewIDPResponse(ResponseTypeAccessToken, accessToken)
		assert.NoError(t, err)
		token, err := parser.ParseResponse(idpResponse)
		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.Equal(t, accessToken.ExpiresOn, token.ExpirationOn())
		assert.Equal(t, accessToken.Token, token.RawCredentials())
	})
	t.Run("Default IdentityProviderResponseParser with type RawToken", func(t *testing.T) {
		idpResponse, err := NewIDPResponse(ResponseTypeRawToken, testJWTtoken)
		assert.NoError(t, err)
		token, err := parser.ParseResponse(idpResponse)
		assert.NoError(t, err)
		assert.NotNil(t, token)
	})

	t.Run("Default IdentityProviderResponseParser with expired JWT Token", func(t *testing.T) {
		idpResponse, err := NewIDPResponse(ResponseTypeRawToken, testJWTExpiredToken)
		assert.NoError(t, err)
		token, err := parser.ParseResponse(idpResponse)
		assert.Error(t, err)
		assert.Nil(t, token)
	})

	t.Run("Default IdentityProviderResponseParser with zero expiry JWT Token", func(t *testing.T) {
		idpResponse, err := NewIDPResponse(ResponseTypeRawToken, testJWTWithZeroExpiryToken)
		assert.NoError(t, err)
		token, err := parser.ParseResponse(idpResponse)
		assert.Error(t, err)
		assert.Nil(t, token)
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
		token, err := parser.ParseResponse(resp)
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
			token, err := parser.ParseResponse(resp)
			assert.Error(t, err)
			assert.Nil(t, token)
		})
	}

	t.Run("Default IdentityProviderResponseParser with response nil", func(t *testing.T) {
		token, err := parser.ParseResponse(nil)
		assert.Error(t, err)
		assert.Nil(t, token)
	})
	t.Run("Default IdentityProviderResponseParser with expired token", func(t *testing.T) {
		authResult := &public.AuthResult{
			ExpiresOn: time.Now().Add(-time.Hour).UTC(),
		}
		idpResponse, err := NewIDPResponse(ResponseTypeAuthResult,
			authResult)
		assert.NoError(t, err)
		token, err := parser.ParseResponse(idpResponse)
		assert.Error(t, err)
		assert.Nil(t, token)
	})
	t.Run("Default IdentityProviderResponseParser with token that expired", func(t *testing.T) {
		authResult := &public.AuthResult{
			ExpiresOn: time.Now().Add(-time.Hour).UTC(),
		}
		idpResponse, err := NewIDPResponse(ResponseTypeAuthResult,
			authResult)
		assert.NoError(t, err)
		token, err := parser.ParseResponse(idpResponse)
		assert.Error(t, err)
		assert.Nil(t, token)
	})
}

func TestEntraidTokenManager_GetToken(t *testing.T) {
	t.Parallel()
	t.Run("GetToken", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		listener := &mockTokenListener{}
		mParser := &mockIdentityProviderResponseParser{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{
				IdentityProviderResponseParser: mParser,
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
		mParser.On("ParseResponse", rawResponse).Return(testTokenValid, nil)
		listener.On("OnTokenNext", testTokenValid).Return()

		cancel, err := tokenManager.Start(listener)
		assert.NotNil(t, cancel)
		assert.NoError(t, err)
		assert.NotNil(t, tm.listener)

		token, err := tokenManager.GetToken(false)
		assert.NoError(t, err)
		assert.NotNil(t, token)

	})

	t.Run("GetToken with parse error", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		listener := &mockTokenListener{}
		mParser := &mockIdentityProviderResponseParser{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{
				IdentityProviderResponseParser: mParser,
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
		mParser.On("ParseResponse", rawResponse).Return(nil, fmt.Errorf("parse error"))
		listener.On("OnTokenError", mock.Anything).Return()

		cancel, err := tokenManager.Start(listener)
		assert.Error(t, err)
		assert.Nil(t, cancel)
		assert.NotNil(t, tm.listener)
	})
	t.Run("GetToken with expired token", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{},
		)
		assert.NoError(t, err)

		authResult := &public.AuthResult{
			ExpiresOn: time.Now().Add(-time.Hour).UTC(),
		}
		idpResponse, err := NewIDPResponse(ResponseTypeAuthResult,
			authResult)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		tm, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)
		assert.Nil(t, tm.listener)

		idp.On("RequestToken").Return(idpResponse, nil)

		token, err := tokenManager.GetToken(false)
		assert.Error(t, err)
		assert.Nil(t, token)
	})

	t.Run("GetToken with nil token", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{},
		)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		_, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)

		rawResponse, err := NewIDPResponse(ResponseTypeRawToken, "test")
		assert.NoError(t, err)

		idp.On("RequestToken").Return(rawResponse, nil)

		token, err := tokenManager.GetToken(false)
		assert.Error(t, err)
		assert.Nil(t, token)
	})

	t.Run("GetToken with nil from parser", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		mParser := &mockIdentityProviderResponseParser{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{
				IdentityProviderResponseParser: mParser,
			},
		)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		_, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)

		idpResponse, err := NewIDPResponse(ResponseTypeRawToken, "test")
		assert.NoError(t, err)
		idp.On("RequestToken").Return(idpResponse, nil)
		mParser.On("ParseResponse", idpResponse).Return(nil, nil)

		token, err := tokenManager.GetToken(false)
		assert.Error(t, err)
		assert.Nil(t, token)
	})

	t.Run("GetToken with idp error", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		mParser := &mockIdentityProviderResponseParser{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{
				IdentityProviderResponseParser: mParser,
			},
		)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		_, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)

		idp.On("RequestToken").Return(nil, fmt.Errorf("idp error"))

		token, err := tokenManager.GetToken(false)
		assert.Error(t, err)
		assert.Nil(t, token)
	})
}

func TestEntraidTokenManager_durationToRenewal(t *testing.T) {
	// Test the durationToRenewal function
	t.Parallel()
	t.Run("durationToRenewal", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		tokenManager, err := NewTokenManager(idp, TokenManagerOptions{
			LowerRefreshBoundMs: 1000 * 60 * 60, // 1 hour
		})
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		tm, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)

		result := tm.durationToRenewal()
		// returns 0 for nil token
		assert.Equal(t, time.Duration(0), result)

		// get token that expires before the lower bound
		assert.NotPanics(t, func() {
			expiresSoon := &public.AuthResult{
				ExpiresOn: time.Now().Add(time.Duration(tm.lowerBoundDuration) - time.Minute).UTC(),
			}
			idpResponse, err := NewIDPResponse(ResponseTypeAuthResult,
				expiresSoon)
			assert.NoError(t, err)
			idp.On("RequestToken").Return(idpResponse, nil).Once()
			tm.token = nil
			_, err = tm.GetToken(false)
			assert.NoError(t, err)
			assert.NotNil(t, tm.token)

			// return zero, should happen now since it expires before the lower bound
			result = tm.durationToRenewal()
			assert.Equal(t, time.Duration(0), result)
		})

		// get token that expires after the lower bound and expirationRefreshRatio to 1
		assert.NotPanics(t, func() {
			tm.expirationRefreshRatio = 1
			expiresAfterlb := &public.AuthResult{
				ExpiresOn: time.Now().Add(time.Duration(tm.lowerBoundDuration) + time.Hour).UTC(),
			}
			idpResponse, err := NewIDPResponse(ResponseTypeAuthResult,
				expiresAfterlb)
			assert.NoError(t, err)
			idp.On("RequestToken").Return(idpResponse, nil).Once()
			tm.token = nil
			_, err = tm.GetToken(false)
			assert.NoError(t, err)
			assert.NotNil(t, tm.token)

			// return time to lower bound, if the returned time will be after the lower bound
			result = tm.durationToRenewal()
			assert.InDelta(t, time.Until(tm.token.expiresOn.Add(-1*tm.lowerBoundDuration)), result, float64(time.Second))
		})

	})
}

func TestEntraidTokenManager_Streaming(t *testing.T) {
	t.Parallel()
	t.Run("Start and Close", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		listener := &mockTokenListener{}
		mParser := &mockIdentityProviderResponseParser{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{
				IdentityProviderResponseParser: mParser,
			},
		)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		tm, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)
		assert.Nil(t, tm.listener)

		expiresIn := time.Second
		expiresOn := time.Now().Add(expiresIn).UTC()
		authResult := &public.AuthResult{
			ExpiresOn: expiresOn,
		}
		idpResponse, err := NewIDPResponse(ResponseTypeAuthResult,
			authResult)
		assert.NoError(t, err)

		idp.On("RequestToken").Return(idpResponse, nil).Once()
		token := NewToken(
			"test",
			"test",
			"test",
			expiresOn,
			time.Now(),
			int64(time.Until(expiresOn)),
		)

		mParser.On("ParseResponse", idpResponse).Return(token, nil).Once()
		listener.On("OnTokenNext", token).Return().Once()

		cancel, err := tokenManager.Start(listener)
		assert.NotNil(t, cancel)
		assert.NoError(t, err)
		assert.NotNil(t, tm.listener)

		toRenewal := tm.durationToRenewal()
		assert.NotEqual(t, time.Duration(0), toRenewal)
		assert.NotEqual(t, expiresIn, toRenewal)
		assert.True(t, expiresIn > toRenewal)
		<-time.After(toRenewal / 10)
		assert.NotNil(t, tm.listener)
		assert.NoError(t, tokenManager.Close())
		assert.Nil(t, tm.listener)
		assert.Panics(t, func() {
			close(tm.closed)
		})

		<-time.After(toRenewal)
		assert.Error(t, tokenManager.Close())
		mock.AssertExpectationsForObjects(t, idp, mParser, listener)
	})

	t.Run("Start and Listen with 0 renewal duration", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		listener := &mockTokenListener{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{
				LowerRefreshBoundMs: 1000 * 60 * 60, // 1 hour
			},
		)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		tm, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)
		assert.Nil(t, tm.listener)

		assert.NoError(t, err)

		expiresIn := time.Second
		expiresOn := time.Now().Add(expiresIn).UTC()
		res := &public.AuthResult{
			ExpiresOn: expiresOn,
		}
		idpResponse, err := NewIDPResponse(ResponseTypeAuthResult,
			res)
		assert.NoError(t, err)
		idp.On("RequestToken").Run(func(args mock.Arguments) {
			expiresOn := time.Now().Add(expiresIn).UTC()
			res := &public.AuthResult{
				ExpiresOn: expiresOn,
			}
			response := idpResponse.(*authResult)
			response.authResult = res
		}).Return(idpResponse, nil)

		listener.On("OnTokenNext", mock.AnythingOfType("*entraid.Token")).Return()

		cancel, err := tokenManager.Start(listener)
		assert.NotNil(t, cancel)
		assert.NoError(t, err)
		assert.NotNil(t, tm.listener)

		toRenewal := tm.durationToRenewal()
		assert.Equal(t, time.Duration(0), toRenewal)
		assert.True(t, expiresIn > toRenewal)

		<-time.After(time.Duration(tm.retryOptions.InitialDelayMs+100) * time.Millisecond)

		idp.AssertNumberOfCalls(t, "RequestToken", 2)
		listener.AssertNumberOfCalls(t, "OnTokenNext", 2)
		mock.AssertExpectationsForObjects(t, idp, listener)
	})

	t.Run("Start and Listen", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		listener := &mockTokenListener{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{},
		)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		tm, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)
		assert.Nil(t, tm.listener)

		assert.NoError(t, err)

		expiresIn := time.Second
		expiresOn := time.Now().Add(expiresIn).UTC()
		res := &public.AuthResult{
			ExpiresOn: expiresOn,
		}
		idpResponse, err := NewIDPResponse(ResponseTypeAuthResult,
			res)
		assert.NoError(t, err)
		idp.On("RequestToken").Run(func(args mock.Arguments) {
			expiresOn := time.Now().Add(expiresIn).UTC()
			res := &public.AuthResult{
				ExpiresOn: expiresOn,
			}
			response := idpResponse.(*authResult)
			response.authResult = res
		}).Return(idpResponse, nil)

		listener.On("OnTokenNext", mock.AnythingOfType("*entraid.Token")).Return()

		cancel, err := tokenManager.Start(listener)
		assert.NotNil(t, cancel)
		assert.NoError(t, err)
		assert.NotNil(t, tm.listener)

		toRenewal := tm.durationToRenewal()
		assert.NotEqual(t, time.Duration(0), toRenewal)
		assert.NotEqual(t, expiresIn, toRenewal)
		assert.True(t, expiresIn > toRenewal)

		<-time.After(toRenewal + time.Second)

		mock.AssertExpectationsForObjects(t, idp, listener)
	})

	t.Run("Start and Listen with retriable error", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		listener := &mockTokenListener{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{},
		)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		tm, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)
		assert.Nil(t, tm.listener)

		assert.NoError(t, err)

		expiresIn := time.Second
		expiresOn := time.Now().Add(expiresIn).UTC()
		res := &public.AuthResult{
			ExpiresOn: expiresOn,
		}
		idpResponse, err := NewIDPResponse(ResponseTypeAuthResult,
			res)
		assert.NoError(t, err)

		noErrCall := idp.On("RequestToken").Run(func(args mock.Arguments) {
			expiresOn := time.Now().Add(expiresIn).UTC()
			res := &public.AuthResult{
				ExpiresOn: expiresOn,
			}
			response := idpResponse.(*authResult)
			response.authResult = res
		}).Return(idpResponse, nil)

		listener.On("OnTokenNext", mock.AnythingOfType("*entraid.Token")).Return()
		listener.On("OnTokenError", mock.Anything).Run(func(args mock.Arguments) {
			err := args.Get(0)
			assert.NotNil(t, err)
			log.Printf("Found TOKEN Error: %v", err)
		}).Return().Maybe()

		cancel, err := tokenManager.Start(listener)
		assert.NotNil(t, cancel)
		assert.NoError(t, err)
		assert.NotNil(t, tm.listener)

		noErrCall.Unset()
		returnErr := newMockError(true)
		idp.On("RequestToken").Return(nil, returnErr)

		toRenewal := tm.durationToRenewal()
		assert.NotEqual(t, time.Duration(0), toRenewal)
		assert.NotEqual(t, expiresIn, toRenewal)
		assert.True(t, expiresIn > toRenewal)
		<-time.After(toRenewal + 100*time.Millisecond)
		idp.AssertNumberOfCalls(t, "RequestToken", 2)
		listener.AssertNumberOfCalls(t, "OnTokenNext", 1)
		mock.AssertExpectationsForObjects(t, idp, listener)
	})

	t.Run("Start and Listen with NOT retriable error", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		listener := &mockTokenListener{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{},
		)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		tm, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)
		assert.Nil(t, tm.listener)

		assert.NoError(t, err)

		expiresIn := time.Second
		expiresOn := time.Now().Add(expiresIn).UTC()
		res := &public.AuthResult{
			ExpiresOn: expiresOn,
		}
		idpResponse, err := NewIDPResponse(ResponseTypeAuthResult,
			res)
		assert.NoError(t, err)

		noErrCall := idp.On("RequestToken").Run(func(args mock.Arguments) {
			expiresOn := time.Now().Add(expiresIn).UTC()
			res := &public.AuthResult{
				ExpiresOn: expiresOn,
			}
			response := idpResponse.(*authResult)
			response.authResult = res
		}).Return(idpResponse, nil)

		listener.On("OnTokenNext", mock.AnythingOfType("*entraid.Token")).Return()
		listener.On("OnTokenError", mock.Anything).Run(func(args mock.Arguments) {
			err := args.Get(0).(error)
			assert.NotNil(t, err)
		}).Return()

		cancel, err := tokenManager.Start(listener)
		assert.NotNil(t, cancel)
		assert.NoError(t, err)
		assert.NotNil(t, tm.listener)

		noErrCall.Unset()
		returnErr := newMockError(false)
		idp.On("RequestToken").Return(nil, returnErr)

		toRenewal := tm.durationToRenewal()
		assert.NotEqual(t, time.Duration(0), toRenewal)
		assert.NotEqual(t, expiresIn, toRenewal)
		assert.True(t, expiresIn > toRenewal)
		<-time.After(toRenewal + 5*time.Millisecond)

		idp.AssertNumberOfCalls(t, "RequestToken", 2)
		listener.AssertNumberOfCalls(t, "OnTokenNext", 1)
		listener.AssertNumberOfCalls(t, "OnTokenError", 1)
		mock.AssertExpectationsForObjects(t, idp, listener)
	})

	t.Run("Start and Listen with retriable error - max retries", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		listener := &mockTokenListener{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{},
		)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		tm, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)
		assert.Nil(t, tm.listener)

		assert.NoError(t, err)

		expiresIn := time.Second
		expiresOn := time.Now().Add(expiresIn).UTC()
		res := &public.AuthResult{
			ExpiresOn: expiresOn,
		}
		idpResponse, err := NewIDPResponse(ResponseTypeAuthResult,
			res)
		assert.NoError(t, err)

		noErrCall := idp.On("RequestToken").Run(func(args mock.Arguments) {
			expiresOn := time.Now().Add(expiresIn).UTC()
			res := &public.AuthResult{
				ExpiresOn: expiresOn,
			}
			response := idpResponse.(*authResult)
			response.authResult = res
		}).Return(idpResponse, nil)

		listener.On("OnTokenNext", mock.AnythingOfType("*entraid.Token")).Return()
		maxAttemptsReached := make(chan struct{})
		listener.On("OnTokenError", mock.Anything).Run(func(args mock.Arguments) {
			err := args.Get(0).(error)
			assert.NotNil(t, err)
			assert.ErrorContains(t, err, "max attempts reached")
			close(maxAttemptsReached)
		}).Return()

		cancel, err := tokenManager.Start(listener)
		assert.NotNil(t, cancel)
		assert.NoError(t, err)
		assert.NotNil(t, tm.listener)

		noErrCall.Unset()
		returnErr := newMockError(true)
		idp.On("RequestToken").Return(nil, returnErr)

		toRenewal := tm.durationToRenewal()
		assert.NotEqual(t, time.Duration(0), toRenewal)
		assert.NotEqual(t, expiresIn, toRenewal)
		assert.True(t, expiresIn > toRenewal)

		select {
		case <-time.After(toRenewal + time.Duration(tm.retryOptions.MaxAttempts*tm.retryOptions.MaxDelayMs)*time.Millisecond):
			assert.Fail(t, "Timeout - max retries not reached ")
		case <-maxAttemptsReached:
		}

		// maxAttempts + the initial one
		idp.AssertNumberOfCalls(t, "RequestToken", tm.retryOptions.MaxAttempts+1)
		listener.AssertNumberOfCalls(t, "OnTokenNext", 1)
		listener.AssertNumberOfCalls(t, "OnTokenError", 1)
		mock.AssertExpectationsForObjects(t, idp, listener)
	})

	t.Run("Start and Listen and close during retries", func(t *testing.T) {
		idp := &mockIdentityProvider{}
		listener := &mockTokenListener{}
		tokenManager, err := NewTokenManager(idp,
			TokenManagerOptions{
				RetryOptions: RetryOptions{
					MaxAttempts: 100,
				},
			},
		)
		assert.NoError(t, err)
		assert.NotNil(t, tokenManager)
		tm, ok := tokenManager.(*entraidTokenManager)
		assert.True(t, ok)
		assert.Nil(t, tm.listener)

		assert.NoError(t, err)

		expiresIn := time.Second
		expiresOn := time.Now().Add(expiresIn).UTC()
		res := &public.AuthResult{
			ExpiresOn: expiresOn,
		}
		idpResponse, err := NewIDPResponse(ResponseTypeAuthResult,
			res)
		assert.NoError(t, err)

		noErrCall := idp.On("RequestToken").Run(func(args mock.Arguments) {
			expiresOn := time.Now().Add(expiresIn).UTC()
			res := &public.AuthResult{
				ExpiresOn: expiresOn,
			}
			response := idpResponse.(*authResult)
			response.authResult = res
		}).Return(idpResponse, nil)

		listener.On("OnTokenNext", mock.AnythingOfType("*entraid.Token")).Return()
		maxAttemptsReached := make(chan struct{})
		listener.On("OnTokenError", mock.Anything).Run(func(args mock.Arguments) {
			err := args.Get(0).(error)
			assert.NotNil(t, err)
			assert.ErrorContains(t, err, "max attempts reached")
			close(maxAttemptsReached)
		}).Return().Maybe()

		cancel, err := tokenManager.Start(listener)
		assert.NotNil(t, cancel)
		assert.NoError(t, err)
		assert.NotNil(t, tm.listener)

		noErrCall.Unset()
		returnErr := newMockError(true)
		idp.On("RequestToken").Return(nil, returnErr)

		toRenewal := tm.durationToRenewal()
		assert.NotEqual(t, time.Duration(0), toRenewal)
		assert.NotEqual(t, expiresIn, toRenewal)
		assert.True(t, expiresIn > toRenewal)

		<-time.After(toRenewal + 50*time.Millisecond)
		assert.Nil(t, cancel())

		select {
		case <-maxAttemptsReached:
			assert.Fail(t, "Max retries reached, token manager not closed")
		case <-tm.closed:
		}

		<-time.After(50 * time.Millisecond)

		// maxAttempts + the initial one
		idp.AssertNumberOfCalls(t, "RequestToken", 2)
		listener.AssertNumberOfCalls(t, "OnTokenError", 0)
		mock.AssertExpectationsForObjects(t, idp, listener)
	})
}
