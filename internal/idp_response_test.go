package internal

import (
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

func TestIDPResp_Type(t *testing.T) {
	tests := []struct {
		name       string
		resultType string
		want       string
	}{
		{
			name:       "AuthResult type",
			resultType: "AuthResult",
			want:       "AuthResult",
		},
		{
			name:       "Empty type",
			resultType: "",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &IDPResp{
				ResultType: tt.resultType,
			}
			if got := resp.Type(); got != tt.want {
				t.Errorf("IDPResp.Type() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIDPResp_AuthResult(t *testing.T) {
	now := time.Now()
	authResult := &public.AuthResult{
		AccessToken: "test-token",
		ExpiresOn:   now,
	}

	tests := []struct {
		name          string
		authResult    *public.AuthResult
		wantToken     string
		wantExpiresOn time.Time
	}{
		{
			name:          "With AuthResult",
			authResult:    authResult,
			wantToken:     "test-token",
			wantExpiresOn: now,
		},
		{
			name:          "Nil AuthResult",
			authResult:    nil,
			wantToken:     "",
			wantExpiresOn: time.Time{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &IDPResp{
				AuthResultVal: tt.authResult,
			}
			got := resp.AuthResult()
			if got.AccessToken != tt.wantToken {
				t.Errorf("IDPResp.AuthResult().AccessToken = %v, want %v", got.AccessToken, tt.wantToken)
			}
			if !got.ExpiresOn.Equal(tt.wantExpiresOn) {
				t.Errorf("IDPResp.AuthResult().ExpiresOn = %v, want %v", got.ExpiresOn, tt.wantExpiresOn)
			}
		})
	}
}

func TestIDPResp_AccessToken(t *testing.T) {
	now := time.Now()
	accessToken := &azcore.AccessToken{
		Token:     "test-token",
		ExpiresOn: now,
	}

	tests := []struct {
		name          string
		accessToken   *azcore.AccessToken
		wantToken     string
		wantExpiresOn time.Time
	}{
		{
			name:          "With AccessToken",
			accessToken:   accessToken,
			wantToken:     "test-token",
			wantExpiresOn: now,
		},
		{
			name:          "Nil AccessToken",
			accessToken:   nil,
			wantToken:     "",
			wantExpiresOn: time.Time{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &IDPResp{
				AccessTokenVal: tt.accessToken,
			}
			got := resp.AccessToken()
			if got.Token != tt.wantToken {
				t.Errorf("IDPResp.AccessToken().Token = %v, want %v", got.Token, tt.wantToken)
			}
			if !got.ExpiresOn.Equal(tt.wantExpiresOn) {
				t.Errorf("IDPResp.AccessToken().ExpiresOn = %v, want %v", got.ExpiresOn, tt.wantExpiresOn)
			}
		})
	}
}

func TestIDPResp_RawToken(t *testing.T) {
	tests := []struct {
		name     string
		rawToken string
		want     string
	}{
		{
			name:     "With RawToken",
			rawToken: "test-raw-token",
			want:     "test-raw-token",
		},
		{
			name:     "Empty RawToken",
			rawToken: "",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &IDPResp{
				RawTokenVal: tt.rawToken,
			}
			if got := resp.RawToken(); got != tt.want {
				t.Errorf("IDPResp.RawToken() = %v, want %v", got, tt.want)
			}
		})
	}
}
