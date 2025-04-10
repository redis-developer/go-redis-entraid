package mocks

import (
	"net"
	"os"
	"time"

	"github.com/redis-developer/go-redis-entraid/shared"
	"github.com/redis-developer/go-redis-entraid/token"
	"github.com/stretchr/testify/mock"
)

// testJWTToken is a JWT manager for testing
//
//	{
//	 "iss": "test jwt",
//	 "iat": 1743515011,
//	 "exp": 1775051011,
//	 "aud": "www.example.com",
//	 "sub": "test@test.com",
//	 "oid": "test"
//	}
//
// key: qwertyuiopasdfghjklzxcvbnm123456
const TestJWTToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0IGp3dCIsImlhdCI6MTc0MzUxNTAxMSwiZXhwIjoxNzc1MDUxMDExLCJhdWQiOiJ3d3cuZXhhbXBsZS5jb20iLCJzdWIiOiJ0ZXN0QHRlc3QuY29tIiwib2lkIjoidGVzdCJ9.6RG721V2eFlSLsCRmo53kSRRrTZIe1UPdLZCUEvIarU"

// testJWTExpiredToken is an expired JWT manager for testing
//
// {
// "iss": "test jwt",
// "iat": 1617795148,
// "exp": 1617795148,
// "aud": "www.example.com",
// "sub": "test@test.com",
// "oid": "test"
// }
//
// key: qwertyuiopasdfghjklzxcvbnm123456
const TestJWTExpiredToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0IGp3dCIsImlhdCI6MTYxNzc5NTE0OCwiZXhwIjoxNjE3Nzk1MTQ4LCJhdWQiOiJ3d3cuZXhhbXBsZS5jb20iLCJzdWIiOiJ0ZXN0QHRlc3QuY29tIiwib2lkIjoidGVzdCJ9.IbGPhHRiPYcpUDrhAPf4h3gH1XXBOu560NYT59rUMzc"

// testJWTWithZeroExpiryToken is a JWT manager with zero expiry for testing
//
// {
// "iss": "test jwt",
// "iat": 1744025944,
// "exp": null,
// "aud": "www.example.com",
// "sub": "test@test.com",
// "oid": "test"
// }
// key: qwertyuiopasdfghjklzxcvbnm123456
const TestJWTWithZeroExpiryToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0IGp3dCIsImlhdCI6MTc0NDAyNTk0NCwiZXhwIjpudWxsLCJhdWQiOiJ3d3cuZXhhbXBsZS5jb20iLCJzdWIiOiJ0ZXN0QHRlc3QuY29tIiwib2lkIjoidGVzdCJ9.bLSANIzawE5Y6rgspvvUaRhkBq6Y4E0ggjXlmHRn8ew"

var TestTokenValid = token.New(
	"test",
	"password",
	"test",
	time.Now().Add(time.Hour),
	time.Now(),
	int64(time.Hour),
)

type IdentityProviderResponseParser struct {
	// Mock implementation of the IdentityProviderResponseParser interface
	mock.Mock
}

func (m *IdentityProviderResponseParser) ParseResponse(response shared.IdentityProviderResponse) (*token.Token, error) {
	args := m.Called(response)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*token.Token), args.Error(1)
}

type IdentityProvider struct {
	// Mock implementation of the IdentityProvider interface
	// Add any necessary fields or methods for the mock identity provider here
	mock.Mock
}

func (m *IdentityProvider) RequestToken() (shared.IdentityProviderResponse, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(shared.IdentityProviderResponse), args.Error(1)
}

func NewError(retriable bool) error {
	if retriable {
		return &Error{
			isTimeout:   true,
			isTemporary: true,
			error:       os.ErrDeadlineExceeded,
		}
	} else {
		return &Error{
			isTimeout:   false,
			isTemporary: false,
			error:       os.ErrInvalid,
		}
	}
}

type Error struct {
	// Mock implementation of the network error
	error
	isTimeout   bool
	isTemporary bool
}

func (m *Error) Error() string {
	return "this is mock error"
}

func (m *Error) Timeout() bool {
	return m.isTimeout
}
func (m *Error) Temporary() bool {
	return m.isTemporary
}
func (m *Error) Unwrap() error {
	return m.error
}

func (m *Error) Is(err error) bool {
	return m.error == err
}

var _ net.Error = (*Error)(nil)

type TokenListener struct {
	// Mock implementation of the TokenManagerListener interface
	mock.Mock
	Id int32
}

func (m *TokenListener) OnTokenNext(token *token.Token) {
	_ = m.Called(token)
}

func (m *TokenListener) OnTokenError(err error) {
	_ = m.Called(err)
}
