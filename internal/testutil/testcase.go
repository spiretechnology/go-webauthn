package testutil

import (
	"encoding/json"

	"github.com/spiretechnology/go-webauthn"
)

type TestCase struct {
	Name               string
	RelyingParty       webauthn.RelyingParty
	User               webauthn.User
	RegistrationJSON   string
	AuthenticationJSON string
}

func (tc *TestCase) RegistrationResponse() *webauthn.RegistrationResponse {
	var res webauthn.RegistrationResponse
	if err := json.Unmarshal([]byte(tc.RegistrationJSON), &res); err != nil {
		panic(err)
	}
	return &res
}

func (tc *TestCase) AuthenticationResponse() *webauthn.AuthenticationResponse {
	var res webauthn.AuthenticationResponse
	if err := json.Unmarshal([]byte(tc.AuthenticationJSON), &res); err != nil {
		panic(err)
	}
	return &res
}

func (tc *TestCase) RegistrationChallenge() webauthn.Challenge {
	regResp := tc.RegistrationResponse()
	return webauthn.Challenge(Decode(regResp.Challenge))
}

func (tc *TestCase) AuthenticationChallenge() webauthn.Challenge {
	authResp := tc.AuthenticationResponse()
	return webauthn.Challenge(Decode(authResp.Challenge))
}

func (tc *TestCase) Credential() *webauthn.Credential {
	regResp := tc.RegistrationResponse()
	return &webauthn.Credential{
		ID:           Decode(regResp.CredentialID),
		Type:         "public-key",
		PublicKey:    Decode(regResp.PublicKey),
		PublicKeyAlg: regResp.PublicKeyAlg,
	}
}
