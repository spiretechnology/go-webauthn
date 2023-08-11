package spec

import (
	"encoding/json"

	"github.com/fxamacker/cbor/v2"
	"github.com/spiretechnology/go-webauthn/internal/errutil"
)

// AuthenticatorAttestationResponse is a registration response.
type AuthenticatorAttestationResponse struct {
	ClientDataJSON    []byte
	AttestationObject []byte
}

func (a *AuthenticatorAttestationResponse) DecodeClientData() (*ClientData, error) {
	var clientData ClientData
	if err := json.Unmarshal(a.ClientDataJSON, &clientData); err != nil {
		return nil, errutil.Wrapf(err, "decoding json")
	}
	return &clientData, nil
}

func (a *AuthenticatorAttestationResponse) DecodeAttestationObject() (*AttestationObject, error) {
	var attestationObject AttestationObject
	if err := cbor.Unmarshal(a.AttestationObject, &attestationObject); err != nil {
		return nil, errutil.Wrapf(err, "decoding cbor")
	}
	return &attestationObject, nil
}
