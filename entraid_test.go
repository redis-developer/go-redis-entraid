package entraid

import (
	"github.com/stretchr/testify/mock"
)

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
