package spec

import (
	"encoding/json"

	"github.com/fxamacker/cbor/v2"
	"github.com/spiretechnology/go-webauthn/internal/errutil"
)

// AuthenticatorAttestationResponse is a registration response.
type AuthenticatorAttestationResponse struct {
	ClientDataJSON        []byte
	AttestationObjectCBOR []byte
}

func (a *AuthenticatorAttestationResponse) ClientData() (*ClientData, error) {
	var clientData ClientData
	if err := json.Unmarshal(a.ClientDataJSON, &clientData); err != nil {
		return nil, errutil.Wrapf(err, "decoding json")
	}
	return &clientData, nil
}

func (a *AuthenticatorAttestationResponse) AttestationObject() (*AttestationObject, error) {
	var attestationObject AttestationObject
	if err := cbor.Unmarshal(a.AttestationObjectCBOR, &attestationObject); err != nil {
		return nil, errutil.Wrapf(err, "decoding cbor")
	}
	return &attestationObject, nil
}
