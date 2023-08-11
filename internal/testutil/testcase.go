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

func (tc *TestCase) RegistrationChallenge() [32]byte {
	regResp := tc.RegistrationResponse()
	return [32]byte(Decode(regResp.Challenge))
}

func (tc *TestCase) AuthenticationChallenge() [32]byte {
	authResp := tc.AuthenticationResponse()
	return [32]byte(Decode(authResp.Challenge))
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
