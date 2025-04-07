package entraid

import (
	"context"
	"net"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/stretchr/testify/mock"
)

// testJWTToken is a JWT token for testing
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
const testJWTtoken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0IGp3dCIsImlhdCI6MTc0MzUxNTAxMSwiZXhwIjoxNzc1MDUxMDExLCJhdWQiOiJ3d3cuZXhhbXBsZS5jb20iLCJzdWIiOiJ0ZXN0QHRlc3QuY29tIiwib2lkIjoidGVzdCJ9.6RG721V2eFlSLsCRmo53kSRRrTZIe1UPdLZCUEvIarU"

// testJWTExpiredToken is an expired JWT token for testing
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
const testJWTExpiredToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0IGp3dCIsImlhdCI6MTYxNzc5NTE0OCwiZXhwIjoxNjE3Nzk1MTQ4LCJhdWQiOiJ3d3cuZXhhbXBsZS5jb20iLCJzdWIiOiJ0ZXN0QHRlc3QuY29tIiwib2lkIjoidGVzdCJ9.IbGPhHRiPYcpUDrhAPf4h3gH1XXBOu560NYT59rUMzc"

// testJWTWithZeroExpiryToken is a JWT token with zero expiry for testing
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
const testJWTWithZeroExpiryToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0IGp3dCIsImlhdCI6MTc0NDAyNTk0NCwiZXhwIjpudWxsLCJhdWQiOiJ3d3cuZXhhbXBsZS5jb20iLCJzdWIiOiJ0ZXN0QHRlc3QuY29tIiwib2lkIjoidGVzdCJ9.bLSANIzawE5Y6rgspvvUaRhkBq6Y4E0ggjXlmHRn8ew"

var testTokenValid = NewToken(
	"test",
	"password",
	"test",
	time.Now().Add(time.Hour),
	time.Now(),
	int64(time.Hour),
)

type mockIdentityProviderResponseParser struct {
	// Mock implementation of the IdentityProviderResponseParser interface
	mock.Mock
}

func (m *mockIdentityProviderResponseParser) ParseResponse(response IdentityProviderResponse) (*Token, error) {
	args := m.Called(response)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Token), args.Error(1)
}

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

type mockAzureCredential struct {
	mock.Mock
}

func (m *mockAzureCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return azcore.AccessToken{}, args.Error(1)
	}
	return args.Get(0).(azcore.AccessToken), args.Error(1)
}

type mockCredFactory struct {
	// Mock implementation of the credFactory interface
	mock.Mock
}

func (m *mockCredFactory) NewDefaultAzureCredential(options *azidentity.DefaultAzureCredentialOptions) (defaultAzureCredential, error) {
	args := m.Called(options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(defaultAzureCredential), args.Error(1)
}
