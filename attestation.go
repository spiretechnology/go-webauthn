package webauthn

import (
	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/internal/spec"
)

// AuthenticatorAttestationResponse is the internal response value send by the client in response to a registration ceremony.
type AuthenticatorAttestationResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AttestationObject string `json:"attestationObject"`
}

func (a *AuthenticatorAttestationResponse) Decode(codec Codec) (*spec.AuthenticatorAttestationResponse, error) {
	// Decode the clientDataJSON
	clientDataJSONBytes, err := codec.DecodeString(a.ClientDataJSON)
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding clientDataJSON")
	}

	// Decode the attestationObject
	attestationObjectBytes, err := codec.DecodeString(a.AttestationObject)
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding attestationObject")
	}

	// Wrap it in the spec type
	return &spec.AuthenticatorAttestationResponse{
		ClientDataJSON:    clientDataJSONBytes,
		AttestationObject: attestationObjectBytes,
	}, nil
}
