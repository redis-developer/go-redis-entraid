package identity

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/redis-developer/go-redis-entraid/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// write tests for azure_default_identity_provider.go
// using the testing package
// and the entraid package
// and the github.com/stretchr/testify/assert package
// and the github.com/Azure/azure-sdk-for-go/sdk/azidentity package
// and the github.com/Azure/azure-sdk-for-go/sdk/azcore/policy package
// and the github.com/Azure/azure-sdk-for-go/sdk/azcore package

func TestNewDefaultAzureIdentityProvider(t *testing.T) {
	// Create a new DefaultAzureIdentityProvider with default options
	provider, err := NewDefaultAzureIdentityProvider(DefaultAzureIdentityProviderOptions{})
	if err != nil {
		t.Fatalf("failed to create DefaultAzureIdentityProvider: %v", err)
	}

	// Check if the provider is not nil
	if provider == nil {
		t.Fatal("provider should not be nil")
	}

	if provider.scopes == nil {
		t.Fatal("provider.scopes should not be nil")
	}

	assert.Contains(t, provider.scopes, RedisScopeDefault, "provider should contain default scope")
}
func TestAzureDefaultIdentityProvider_RequestToken(t *testing.T) {
	// Create a new DefaultAzureIdentityProvider with default options
	provider, err := NewDefaultAzureIdentityProvider(DefaultAzureIdentityProviderOptions{})
	if err != nil {
		t.Fatalf("failed to create DefaultAzureIdentityProvider: %v", err)
	}

	// Request a manager from the provider in incorrect environment
	// should fail.
	token, err := provider.RequestToken()
	assert.Nil(t, token, "manager should be nil")
	assert.Error(t, err, "failed to request manager")

	// use mockAzureCredential to simulate the environment
	mToken := azcore.AccessToken{
		Token: testJWTToken,
	}
	mCreds := &mockAzureCredential{}
	mCreds.On("GetToken", mock.Anything, mock.Anything).Return(mToken, nil)
	mCredFactory := &mockCredFactory{}
	mCredFactory.On("NewDefaultAzureCredential", mock.Anything).Return(mCreds, nil)
	provider.credFactory = mCredFactory
	token, err = provider.RequestToken()
	assert.NotNil(t, token, "manager should not be nil")
	assert.NoError(t, err, "failed to request manager")
	assert.Equal(t, shared.ResponseTypeAccessToken, token.Type(), "manager type should be access manager")
	assert.Equal(t, mToken, token.AccessToken(), "access manager should be equal to testJWTToken")
}

func TestAzureDefaultIdentityProvider_RequestTokenWithScopes(t *testing.T) {
	// Create a new DefaultAzureIdentityProvider with custom scopes
	scopes := []string{"https://example.com/.default"}
	provider, err := NewDefaultAzureIdentityProvider(DefaultAzureIdentityProviderOptions{
		Scopes: scopes,
	})
	if err != nil {
		t.Fatalf("failed to create DefaultAzureIdentityProvider: %v", err)
	}

	t.Run("RequestToken with custom scopes", func(t *testing.T) {
		// Request a manager from the provider
		token, err := provider.RequestToken()
		assert.Nil(t, token, "manager should be nil")
		assert.Error(t, err, "failed to request manager")

		// use mockAzureCredential to simulate the environment
		mToken := azcore.AccessToken{
			Token: testJWTToken,
		}
		mCreds := &mockAzureCredential{}
		mCreds.On("GetToken", mock.Anything, policy.TokenRequestOptions{Scopes: scopes}).Return(mToken, nil)
		mCredFactory := &mockCredFactory{}
		mCredFactory.On("NewDefaultAzureCredential", mock.Anything).Return(mCreds, nil)
		provider.credFactory = mCredFactory
		token, err = provider.RequestToken()
		assert.NotNil(t, token, "manager should not be nil")
		assert.NoError(t, err, "failed to request manager")
		assert.Equal(t, shared.ResponseTypeAccessToken, token.Type(), "manager type should be access manager")
		assert.Equal(t, mToken, token.AccessToken(), "access manager should be equal to testJWTToken")
	})
	t.Run("RequestToken with error from credFactory", func(t *testing.T) {
		// use mockAzureCredential to simulate the environment
		mCredFactory := &mockCredFactory{}
		mCredFactory.On("NewDefaultAzureCredential", mock.Anything).Return(nil, assert.AnError)
		provider.credFactory = mCredFactory
		token, err := provider.RequestToken()
		assert.Nil(t, token, "manager should be nil")
		assert.Error(t, err, "failed to request manager")
	})
}
