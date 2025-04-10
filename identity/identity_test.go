package identity

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/redis-developer/go-redis-entraid/internal/mocks"
	"github.com/stretchr/testify/mock"
)

var testJWTToken = mocks.TestJWTToken

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

func (m *mockCredFactory) NewDefaultAzureCredential(options *azidentity.DefaultAzureCredentialOptions) (azureCredential, error) {
	args := m.Called(options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(azureCredential), args.Error(1)
}

type mockConfidentialCredentialFactory struct {
	// Mock implementation of the confidentialCredFactory interface
	mock.Mock
}

func (m *mockConfidentialCredentialFactory) NewCredFromSecret(clientSecret string) (confidential.Credential, error) {
	args := m.Called(clientSecret)
	if args.Get(0) == nil {
		return confidential.Credential{}, args.Error(1)
	}
	return args.Get(0).(confidential.Credential), args.Error(1)
}

func (m *mockConfidentialCredentialFactory) NewCredFromCert(clientCert []*x509.Certificate, clientPrivateKey crypto.PrivateKey) (confidential.Credential, error) {
	args := m.Called(clientCert, clientPrivateKey)
	if args.Get(0) == nil {
		return confidential.Credential{}, args.Error(1)
	}
	return args.Get(0).(confidential.Credential), args.Error(1)
}

type mockConfidentialTokenClient struct {
	// Mock implementation of the confidentialTokenClient interface
	mock.Mock
}

func (m *mockConfidentialTokenClient) AcquireTokenByCredential(ctx context.Context, scopes []string, options ...confidential.AcquireByCredentialOption) (confidential.AuthResult, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return confidential.AuthResult{}, args.Error(1)
	}
	return args.Get(0).(confidential.AuthResult), args.Error(1)
}
