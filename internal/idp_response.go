package internal

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

type IDPResp struct {
	ResultType     string
	AuthResultVal  *public.AuthResult
	AccessTokenVal *azcore.AccessToken
	RawTokenVal    string
}

func (a *IDPResp) Type() string {
	return a.ResultType
}

func (a *IDPResp) AuthResult() public.AuthResult {
	if a.AuthResultVal == nil {
		return public.AuthResult{}
	}
	return *a.AuthResultVal
}

func (a *IDPResp) AccessToken() azcore.AccessToken {
	if a.AccessTokenVal == nil {
		return azcore.AccessToken{}
	}
	return *a.AccessTokenVal
}

func (a *IDPResp) RawToken() string {
	return a.RawTokenVal
}
