package entraid

import (
	"errors"
	"testing"
	"time"

	"github.com/redis-developer/go-redis-entraid/identity"
	"github.com/redis-developer/go-redis-entraid/manager"
	"github.com/redis-developer/go-redis-entraid/shared"
	"github.com/redis-developer/go-redis-entraid/token"
	"github.com/redis/go-redis/v9/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTokenManager implements the TokenManager interface for testing
type mockTokenManager struct {
	token *token.Token
	err   error
}

func (m *mockTokenManager) GetToken(forceRefresh bool) (*token.Token, error) {
	return m.token, m.err
}

func (m *mockTokenManager) Start(listener manager.TokenListener) (manager.CancelFunc, error) {
	if m.err != nil {
		listener.OnTokenError(m.err)
		return nil, m.err
	}

	listener.OnTokenNext(m.token)
	return func() error { return nil }, nil
}

func (m *mockTokenManager) Close() error {
	return nil
}

// mockCredentialsListener implements the CredentialsListener interface for testing
type mockCredentialsListener struct {
	LastTokenCh chan string
	LastErrCh   chan error
}

func (m *mockCredentialsListener) OnNext(credentials auth.Credentials) {
	if m.LastTokenCh == nil {
		m.LastTokenCh = make(chan string)
	}
	m.LastTokenCh <- credentials.RawCredentials()
}

func (m *mockCredentialsListener) OnError(err error) {
	if m.LastErrCh == nil {
		m.LastErrCh = make(chan error)
	}
	m.LastErrCh <- err
}

// testTokenManagerFactory is a factory function that returns a mock token manager
func testTokenManagerFactory(token *token.Token, err error) func(shared.IdentityProvider, manager.TokenManagerOptions) (manager.TokenManager, error) {
	return func(provider shared.IdentityProvider, options manager.TokenManagerOptions) (manager.TokenManager, error) {
		return &mockTokenManager{
			token: token,
			err:   err,
		}, nil
	}
}

func TestNewManagedIdentityCredentialsProvider(t *testing.T) {
	tests := []struct {
		name          string
		options       ManagedIdentityCredentialsProviderOptions
		expectedError error
	}{
		{
			name: "valid managed identity options",
			options: ManagedIdentityCredentialsProviderOptions{
				CredentialsProviderOptions: CredentialsProviderOptions{
					ClientID: "test-client-id",
					TokenManagerOptions: manager.TokenManagerOptions{
						ExpirationRefreshRatio: 0.7,
					},
				},
				ManagedIdentityProviderOptions: identity.ManagedIdentityProviderOptions{
					UserAssignedClientID: "test-client-id",
					ManagedIdentityType:  identity.UserAssignedIdentity,
					Scopes:               []string{identity.RedisScopeDefault},
				},
			},
			expectedError: nil,
		},
		{
			name: "system assigned identity",
			options: ManagedIdentityCredentialsProviderOptions{
				CredentialsProviderOptions: CredentialsProviderOptions{
					TokenManagerOptions: manager.TokenManagerOptions{
						ExpirationRefreshRatio: 0.7,
					},
				},
				ManagedIdentityProviderOptions: identity.ManagedIdentityProviderOptions{
					ManagedIdentityType: identity.SystemAssignedIdentity,
					Scopes:              []string{identity.RedisScopeDefault},
				},
			},
			expectedError: nil,
		},
		{
			name: "invalid managed identity type",
			options: ManagedIdentityCredentialsProviderOptions{
				ManagedIdentityProviderOptions: identity.ManagedIdentityProviderOptions{
					ManagedIdentityType: "invalid-type",
				},
			},
			expectedError: errors.New("invalid managed identity type"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test token
			testToken := token.New(
				"test",
				"test",
				"mock-token",
				time.Now().Add(time.Hour),
				time.Now(),
				int64(time.Hour),
			)

			// Set the token manager factory in the options
			tt.options.tokenManagerFactory = testTokenManagerFactory(testToken, nil)

			provider, err := NewManagedIdentityCredentialsProvider(tt.options)
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)

				// Test the provider with a mock listener
				listener := &mockCredentialsListener{LastTokenCh: make(chan string)}
				_, _, err := provider.Subscribe(listener)
				assert.NoError(t, err)
				assert.Equal(t, "mock-token", <-listener.LastTokenCh)
			}
		})
	}
}

func TestNewConfidentialCredentialsProvider(t *testing.T) {
	tests := []struct {
		name          string
		options       ConfidentialCredentialsProviderOptions
		expectedError error
	}{
		{
			name: "valid confidential options with client secret",
			options: ConfidentialCredentialsProviderOptions{
				CredentialsProviderOptions: CredentialsProviderOptions{
					ClientID: "test-client-id",
					TokenManagerOptions: manager.TokenManagerOptions{
						ExpirationRefreshRatio: 0.7,
					},
				},
				ConfidentialIdentityProviderOptions: identity.ConfidentialIdentityProviderOptions{
					ClientID:        "test-client-id",
					CredentialsType: identity.ClientSecretCredentialType,
					ClientSecret:    "test-secret",
					Scopes:          []string{identity.RedisScopeDefault},
					Authority:       identity.AuthorityConfiguration{},
				},
			},
			expectedError: nil,
		},
		{
			name: "missing required fields",
			options: ConfidentialCredentialsProviderOptions{
				ConfidentialIdentityProviderOptions: identity.ConfidentialIdentityProviderOptions{
					CredentialsType: identity.ClientSecretCredentialType,
				},
			},
			expectedError: errors.New("client ID is required"),
		},
		{
			name: "invalid credentials type",
			options: ConfidentialCredentialsProviderOptions{
				ConfidentialIdentityProviderOptions: identity.ConfidentialIdentityProviderOptions{
					ClientID:        "test-client-id",
					CredentialsType: "invalid-type",
				},
			},
			expectedError: errors.New("invalid credentials type"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test token
			testToken := token.New(
				"test",
				"test",
				"mock-token",
				time.Now().Add(time.Hour),
				time.Now(),
				int64(time.Hour),
			)

			// Set the token manager factory in the options
			tt.options.tokenManagerFactory = testTokenManagerFactory(testToken, nil)

			provider, err := NewConfidentialCredentialsProvider(tt.options)
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)

				// Test the provider with a mock listener
				listener := &mockCredentialsListener{LastTokenCh: make(chan string)}
				_, _, err := provider.Subscribe(listener)
				assert.NoError(t, err)
				assert.Equal(t, "mock-token", <-listener.LastTokenCh)
			}
		})
	}
}

func TestNewDefaultAzureCredentialsProvider(t *testing.T) {
	tests := []struct {
		name          string
		options       DefaultAzureCredentialsProviderOptions
		expectedError error
	}{
		{
			name: "valid default azure options",
			options: DefaultAzureCredentialsProviderOptions{
				CredentialsProviderOptions: CredentialsProviderOptions{
					ClientID: "test-client-id",
					TokenManagerOptions: manager.TokenManagerOptions{
						ExpirationRefreshRatio: 0.7,
					},
				},
				DefaultAzureIdentityProviderOptions: identity.DefaultAzureIdentityProviderOptions{
					Scopes: []string{identity.RedisScopeDefault},
				},
			},
			expectedError: nil,
		},
		{
			name: "empty options",
			options: DefaultAzureCredentialsProviderOptions{
				CredentialsProviderOptions: CredentialsProviderOptions{
					TokenManagerOptions: manager.TokenManagerOptions{
						ExpirationRefreshRatio: 0.7,
					},
				},
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test token
			testToken := token.New(
				"test",
				"test",
				"mock-token",
				time.Now().Add(time.Hour),
				time.Now(),
				int64(time.Hour),
			)

			// Set the token manager factory in the options
			tt.options.tokenManagerFactory = testTokenManagerFactory(testToken, nil)

			provider, err := NewDefaultAzureCredentialsProvider(tt.options)
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)

				// Test the provider with a mock listener
				listener := &mockCredentialsListener{LastTokenCh: make(chan string)}
				_, _, err := provider.Subscribe(listener)
				assert.NoError(t, err)
				assert.Equal(t, "mock-token", <-listener.LastTokenCh)
			}
		})
	}
}

func TestCredentialsProviderErrorHandling(t *testing.T) {
	t.Run("on re-authentication error", func(t *testing.T) {
		options := ConfidentialCredentialsProviderOptions{
			CredentialsProviderOptions: CredentialsProviderOptions{
				ClientID: "test-client-id",
				TokenManagerOptions: manager.TokenManagerOptions{
					ExpirationRefreshRatio: 0.7,
				},
				OnReAuthenticationError: func(err error) error {
					return errors.New("custom re-auth error")
				},
			},
			ConfidentialIdentityProviderOptions: identity.ConfidentialIdentityProviderOptions{
				ClientID:        "test-client-id",
				CredentialsType: identity.ClientSecretCredentialType,
				ClientSecret:    "test-secret",
				Scopes:          []string{identity.RedisScopeDefault},
				Authority:       identity.AuthorityConfiguration{},
			},
		}

		// Create a test token
		testToken := token.New(
			"test",
			"test",
			"mock-token",
			time.Now().Add(time.Hour),
			time.Now(),
			int64(time.Hour),
		)

		// Set the token manager factory in the options
		options.tokenManagerFactory = testTokenManagerFactory(testToken, nil)

		provider, err := NewConfidentialCredentialsProvider(options)
		require.NoError(t, err)
		require.NotNil(t, provider)

		// Test that the error handler is properly set
		// Note: This is a simplified test as actual authentication would require Azure credentials
		assert.NotNil(t, provider)
	})

	t.Run("on retryable error", func(t *testing.T) {
		options := ConfidentialCredentialsProviderOptions{
			CredentialsProviderOptions: CredentialsProviderOptions{
				ClientID: "test-client-id",
				TokenManagerOptions: manager.TokenManagerOptions{
					ExpirationRefreshRatio: 0.7,
				},
				OnRetryableError: func(err error) error {
					return errors.New("custom retry error")
				},
			},
			ConfidentialIdentityProviderOptions: identity.ConfidentialIdentityProviderOptions{
				ClientID:        "test-client-id",
				CredentialsType: identity.ClientSecretCredentialType,
				ClientSecret:    "test-secret",
				Scopes:          []string{identity.RedisScopeDefault},
				Authority:       identity.AuthorityConfiguration{},
			},
		}

		// Create a test token
		testToken := token.New(
			"test",
			"test",
			"mock-token",
			time.Now().Add(time.Hour),
			time.Now(),
			int64(time.Hour),
		)

		// Set the token manager factory in the options
		options.tokenManagerFactory = testTokenManagerFactory(testToken, nil)

		provider, err := NewConfidentialCredentialsProvider(options)
		require.NoError(t, err)
		require.NotNil(t, provider)

		// Test that the error handler is properly set
		// Note: This is a simplified test as actual authentication would require Azure credentials
		assert.NotNil(t, provider)
	})
}

func TestCredentialsProviderInterface(t *testing.T) {
	// Test that all providers implement the StreamingCredentialsProvider interface
	tests := []struct {
		name     string
		provider auth.StreamingCredentialsProvider
	}{
		{
			name: "managed identity provider",
			provider: func() auth.StreamingCredentialsProvider {
				options := ManagedIdentityCredentialsProviderOptions{
					CredentialsProviderOptions: CredentialsProviderOptions{
						ClientID: "test-client-id",
						TokenManagerOptions: manager.TokenManagerOptions{
							ExpirationRefreshRatio: 0.7,
						},
					},
					ManagedIdentityProviderOptions: identity.ManagedIdentityProviderOptions{
						UserAssignedClientID: "test-client-id",
						ManagedIdentityType:  identity.UserAssignedIdentity,
						Scopes:               []string{identity.RedisScopeDefault},
					},
				}

				// Create a test token
				testToken := token.New(
					"test",
					"test",
					"mock-token",
					time.Now().Add(time.Hour),
					time.Now(),
					int64(time.Hour),
				)

				// Set the token manager factory in the options
				options.tokenManagerFactory = testTokenManagerFactory(testToken, nil)

				p, _ := NewManagedIdentityCredentialsProvider(options)
				return p
			}(),
		},
		{
			name: "confidential provider",
			provider: func() auth.StreamingCredentialsProvider {
				options := ConfidentialCredentialsProviderOptions{
					CredentialsProviderOptions: CredentialsProviderOptions{
						ClientID: "test-client-id",
						TokenManagerOptions: manager.TokenManagerOptions{
							ExpirationRefreshRatio: 0.7,
						},
					},
					ConfidentialIdentityProviderOptions: identity.ConfidentialIdentityProviderOptions{
						ClientID:        "test-client-id",
						CredentialsType: identity.ClientSecretCredentialType,
						ClientSecret:    "test-secret",
						Scopes:          []string{identity.RedisScopeDefault},
						Authority:       identity.AuthorityConfiguration{},
					},
				}

				// Create a test token
				testToken := token.New(
					"test",
					"test",
					"mock-token",
					time.Now().Add(time.Hour),
					time.Now(),
					int64(time.Hour),
				)

				// Set the token manager factory in the options
				options.tokenManagerFactory = testTokenManagerFactory(testToken, nil)

				p, _ := NewConfidentialCredentialsProvider(options)
				return p
			}(),
		},
		{
			name: "default azure provider",
			provider: func() auth.StreamingCredentialsProvider {
				options := DefaultAzureCredentialsProviderOptions{
					CredentialsProviderOptions: CredentialsProviderOptions{
						ClientID: "test-client-id",
						TokenManagerOptions: manager.TokenManagerOptions{
							ExpirationRefreshRatio: 0.7,
						},
					},
					DefaultAzureIdentityProviderOptions: identity.DefaultAzureIdentityProviderOptions{
						Scopes: []string{identity.RedisScopeDefault},
					},
				}

				// Create a test token
				testToken := token.New(
					"test",
					"test",
					"mock-token",
					time.Now().Add(time.Hour),
					time.Now(),
					int64(time.Hour),
				)

				// Set the token manager factory in the options
				options.tokenManagerFactory = testTokenManagerFactory(testToken, nil)

				p, _ := NewDefaultAzureCredentialsProvider(options)
				return p
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that the provider implements the interface by calling its methods
			// Note: These are simplified tests as actual authentication would require Azure credentials
			listener := &mockCredentialsListener{}
			credentials, cancel, err := tt.provider.Subscribe(listener)
			assert.NotNil(t, credentials)
			assert.NotNil(t, cancel)
			assert.NoError(t, err)
		})
	}
}
