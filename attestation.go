package webauthn

import (
	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/internal/spec"
	"github.com/spiretechnology/go-webauthn/pkg/codec"
)

// AuthenticatorAttestationResponse is the internal response value send by the client in response to a registration ceremony.
type AuthenticatorAttestationResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AttestationObject string `json:"attestationObject"`
}

func (a *AuthenticatorAttestationResponse) Decode(c codec.Codec) (*spec.AuthenticatorAttestationResponse, error) {
	// Decode the clientDataJSON
	clientDataJSONBytes, err := c.DecodeString(a.ClientDataJSON)
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding clientDataJSON")
	}

	// Decode the attestationObject
	attestationObjectBytes, err := c.DecodeString(a.AttestationObject)
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding attestationObject")
	}

	// Wrap it in the spec type
	return &spec.AuthenticatorAttestationResponse{
		ClientDataJSON:        clientDataJSONBytes,
		AttestationObjectCBOR: attestationObjectBytes,
	}, nil
}
