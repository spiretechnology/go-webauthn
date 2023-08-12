package testutil

import (
	"github.com/spiretechnology/go-webauthn"
	"github.com/spiretechnology/go-webauthn/internal/spec"
)

type TestCase struct {
	Name           string                          `json:"name"`
	RelyingParty   webauthn.RelyingParty           `json:"relyingParty"`
	User           webauthn.User                   `json:"user"`
	Registration   webauthn.RegistrationResponse   `json:"registration"`
	Authentication webauthn.AuthenticationResponse `json:"authentication"`
	Attestation    TestCase_Attestation            `json:"attestation"`
}

type TestCase_Attestation struct {
	Fmt              string   `json:"fmt"`
	Flags            []string `json:"flags"`
	SignCount        uint32   `json:"signCount"`
	AAGUIDHex        string   `json:"aaguidHex"`
	CredIDHex        string   `json:"credIdHex"`
	CredPublicKeyB64 string   `json:"credPublicKeyB64"`
}

func (tc *TestCase) RegistrationChallenge() webauthn.Challenge {
	return webauthn.Challenge(Decode(tc.Registration.Challenge))
}

func (tc *TestCase) AuthenticationChallenge() webauthn.Challenge {
	return webauthn.Challenge(Decode(tc.Authentication.Challenge))
}

func (tc *TestCase) Credential() *webauthn.Credential {
	return &webauthn.Credential{
		ID:           Decode(tc.Registration.CredentialID),
		Type:         "public-key",
		PublicKey:    Decode(tc.Registration.PublicKey),
		PublicKeyAlg: tc.Registration.PublicKeyAlg,
	}
}

func (tca *TestCase_Attestation) FlagsUInt8() uint8 {
	flagsMap := map[string]uint8{
		"UserPresent":            spec.AuthDataFlag_UserPresent,
		"RFU1":                   spec.AuthDataFlag_RFU1,
		"UserVerified":           spec.AuthDataFlag_UserVerified,
		"RFU2":                   spec.AuthDataFlag_RFU2,
		"RFU3":                   spec.AuthDataFlag_RFU3,
		"RFU4":                   spec.AuthDataFlag_RFU4,
		"AttestedCredentialData": spec.AuthDataFlag_AttestedCredentialData,
		"ExtensionData":          spec.AuthDataFlag_ExtensionData,
	}
	var flags uint8
	for _, flag := range tca.Flags {
		flags |= flagsMap[flag]
	}
	return flags
}
