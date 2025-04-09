package manager

import (
	"github.com/redis-developer/go-redis-entraid/internal"
	"github.com/redis-developer/go-redis-entraid/internal/mocks"
)

type mockIdentityProviderResponseParser = mocks.IdentityProviderResponseParser
type mockIdentityProvider = mocks.IdentityProvider
type mockTokenListener = mocks.TokenListener

var newMockError = mocks.NewError
var testTokenValid = mocks.TestTokenValid
var testJWTToken = mocks.TestJWTToken
var testJWTExpiredToken = mocks.TestJWTExpiredToken
var testJWTWithZeroExpiryToken = mocks.TestJWTWithZeroExpiryToken

type authResult = internal.IDPResp
