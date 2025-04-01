package entraid

import (
	"net"
	"time"

	"github.com/stretchr/testify/mock"
)

const testJWTtoken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0IGp3dCIsImlhdCI6MTc0MzUxNTAxMSwiZXhwIjoxNzc1MDUxMDExLCJhdWQiOiJ3d3cuZXhhbXBsZS5jb20iLCJzdWIiOiJ0ZXN0QHRlc3QuY29tIiwib2lkIjoidGVzdCJ9.6RG721V2eFlSLsCRmo53kSRRrTZIe1UPdLZCUEvIarU"

type mockIdentityProvider struct {
	// Mock implementation of the IdentityProvider interface
	// Add any necessary fields or methods for the mock identity provider here
	mock.Mock
}

func (m *mockIdentityProvider) RequestToken() (IdentityProviderResponse, error) {
	args := m.Called()
	return args.Get(0).(IdentityProviderResponse), args.Error(1)
}

// Ensure mockIdentityProvider implements the IdentityProvider interface
var _ IdentityProvider = (*mockIdentityProvider)(nil)

type mockError struct {
	// Mock implementation of the network error
	error
	isTimeout   bool
	isTemporary bool
}

func (m *mockError) Timeout() bool {
	return m.isTimeout
}
func (m *mockError) Temporary() bool {
	return m.isTemporary
}
func (m *mockError) Unwrap() error {
	return m.error
}

func (m *mockError) Is(err error) bool {
	return m.error == err
}

var _ net.Error = (*mockError)(nil)

type mockTokenListener struct {
	// Mock implementation of the TokenManagerListener interface
	mock.Mock
}

var _ TokenListener = (*mockTokenListener)(nil)

func (m *mockTokenListener) OnTokenNext(token *Token) {
	_ = m.Called(token)
}

func (m *mockTokenListener) OnTokenError(err error) {
	_ = m.Called(err)
}

func mockTokenParserFunc(idpResponse IdentityProviderResponse) (*Token, error) {
	if idpResponse != nil && idpResponse.Type() == ResponseTypeRawToken {
		return NewToken(
			"test",
			"password",
			"test",
			time.Now().Add(time.Hour),
			time.Now(),
			int64(time.Hour),
		), nil
	}
	return nil, nil
}
