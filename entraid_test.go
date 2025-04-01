package entraid

import (
	"net"

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
