package identity

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
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
