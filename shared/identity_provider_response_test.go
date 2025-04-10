package shared

import (
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/redis-developer/go-redis-entraid/token"
	"github.com/stretchr/testify/assert"
)

// Mock implementations for testing
type mockIDPResponse struct {
	responseType string
	authResult   *public.AuthResult
	accessToken  *azcore.AccessToken
	rawToken     string
}

func (m *mockIDPResponse) Type() string {
	return m.responseType
}

func (m *mockIDPResponse) AuthResult() public.AuthResult {
	if m.authResult == nil {
		return public.AuthResult{}
	}
	return *m.authResult
}

func (m *mockIDPResponse) AccessToken() azcore.AccessToken {
	if m.accessToken == nil {
		return azcore.AccessToken{}
	}
	return *m.accessToken
}

func (m *mockIDPResponse) RawToken() string {
	return m.rawToken
}

type mockIDPParser struct {
	parseError error
	token      *token.Token
}

func (m *mockIDPParser) ParseResponse(response IdentityProviderResponse) (*token.Token, error) {
	if m.parseError != nil {
		return nil, m.parseError
	}
	return m.token, nil
}

type mockIDP struct {
	response IdentityProviderResponse
	err      error
}

func (m *mockIDP) RequestToken() (IdentityProviderResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.response, nil
}

func TestNewIDPResponse(t *testing.T) {
	tests := []struct {
		name         string
		responseType string
		result       interface{}
		wantErr      bool
	}{
		{
			name:         "Valid AuthResult",
			responseType: ResponseTypeAuthResult,
			result:       &public.AuthResult{},
			wantErr:      false,
		},
		{
			name:         "Valid AccessToken",
			responseType: ResponseTypeAccessToken,
			result:       &azcore.AccessToken{},
			wantErr:      false,
		},
		{
			name:         "Valid RawToken",
			responseType: ResponseTypeRawToken,
			result:       "test-token",
			wantErr:      false,
		},
		{
			name:         "Invalid AuthResult type",
			responseType: ResponseTypeAuthResult,
			result:       "not-an-auth-result",
			wantErr:      true,
		},
		{
			name:         "Invalid AccessToken type",
			responseType: ResponseTypeAccessToken,
			result:       "not-an-access-token",
			wantErr:      true,
		},
		{
			name:         "Invalid RawToken type",
			responseType: ResponseTypeRawToken,
			result:       123,
			wantErr:      true,
		},
		{
			name:         "Unknown response type",
			responseType: "UnknownType",
			result:       nil,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := NewIDPResponse(tt.responseType, tt.result)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, response)
				assert.Equal(t, tt.responseType, response.Type())
			}
		})
	}
}

func TestIdentityProviderResponse(t *testing.T) {
	now := time.Now()
	expires := now.Add(time.Hour)

	authResult := &public.AuthResult{
		AccessToken: "test-access-token",
		ExpiresOn:   expires,
	}

	accessToken := &azcore.AccessToken{
		Token:     "test-access-token",
		ExpiresOn: expires,
	}

	tests := []struct {
		name         string
		response     *mockIDPResponse
		expectedType string
	}{
		{
			name: "AuthResult response",
			response: &mockIDPResponse{
				responseType: ResponseTypeAuthResult,
				authResult:   authResult,
			},
			expectedType: ResponseTypeAuthResult,
		},
		{
			name: "AccessToken response",
			response: &mockIDPResponse{
				responseType: ResponseTypeAccessToken,
				accessToken:  accessToken,
			},
			expectedType: ResponseTypeAccessToken,
		},
		{
			name: "RawToken response",
			response: &mockIDPResponse{
				responseType: ResponseTypeRawToken,
				rawToken:     "test-raw-token",
			},
			expectedType: ResponseTypeRawToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedType, tt.response.Type())

			switch tt.expectedType {
			case ResponseTypeAuthResult:
				result := tt.response.AuthResult()
				assert.Equal(t, authResult.AccessToken, result.AccessToken)
				assert.Equal(t, authResult.ExpiresOn, result.ExpiresOn)
			case ResponseTypeAccessToken:
				token := tt.response.AccessToken()
				assert.Equal(t, accessToken.Token, token.Token)
				assert.Equal(t, accessToken.ExpiresOn, token.ExpiresOn)
			case ResponseTypeRawToken:
				assert.Equal(t, "test-raw-token", tt.response.RawToken())
			}
		})
	}
}

func TestIdentityProvider(t *testing.T) {
	tests := []struct {
		name     string
		provider *mockIDP
		wantErr  bool
	}{
		{
			name: "Successful token request",
			provider: &mockIDP{
				response: &mockIDPResponse{
					responseType: ResponseTypeRawToken,
					rawToken:     "test-token",
				},
			},
			wantErr: false,
		},
		{
			name: "Failed token request",
			provider: &mockIDP{
				err: assert.AnError,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := tt.provider.RequestToken()
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, response)
				assert.Equal(t, ResponseTypeRawToken, response.Type())
				assert.Equal(t, "test-token", response.RawToken())
			}
		})
	}
}

func TestIdentityProviderResponseParser(t *testing.T) {
	now := time.Now()
	expires := now.Add(time.Hour)
	testToken := token.New("test-user", "test-password", "test-token", expires, now, int64(time.Hour.Seconds()))

	tests := []struct {
		name      string
		parser    *mockIDPParser
		response  IdentityProviderResponse
		wantErr   bool
		wantToken *token.Token
	}{
		{
			name: "Successful parse",
			parser: &mockIDPParser{
				token: testToken,
			},
			response: &mockIDPResponse{
				responseType: ResponseTypeRawToken,
				rawToken:     "test-token",
			},
			wantErr:   false,
			wantToken: testToken,
		},
		{
			name: "Failed parse",
			parser: &mockIDPParser{
				parseError: assert.AnError,
			},
			response: &mockIDPResponse{
				responseType: ResponseTypeRawToken,
				rawToken:     "test-token",
			},
			wantErr:   true,
			wantToken: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := tt.parser.ParseResponse(tt.response)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, token)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantToken, token)
			}
		})
	}
}
