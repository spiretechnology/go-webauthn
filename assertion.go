package webauthn

import (
	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/pkg/codec"
	"github.com/spiretechnology/go-webauthn/pkg/spec"
)

// AuthenticatorAssertionResponse is the internal response value send by the client in response to an authentication ceremony.
type AuthenticatorAssertionResponse struct {
	AuthenticatorData string  `json:"authenticatorData"`
	ClientDataJSON    string  `json:"clientDataJSON"`
	Signature         string  `json:"signature"`
	UserHandle        *string `json:"userHandle"`
}

func (a *AuthenticatorAssertionResponse) Decode(c codec.Codec) (*spec.AuthenticatorAssertionResponse, error) {
	// Decode the clientDataJSON
	clientDataJSONBytes, err := c.DecodeString(a.ClientDataJSON)
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding clientDataJSON")
	}

	// Decode the authenticator data
	authenticatorDataBytes, err := c.DecodeString(a.AuthenticatorData)
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding authenticator data")
	}

	// Decode the signature string
	signatureBytes, err := c.DecodeString(a.Signature)
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding signature")
	}

	// Decode the user handle
	var userHandleBytes []byte
	if a.UserHandle != nil {
		userHandleBytes, err = c.DecodeString(*a.UserHandle)
		if err != nil {
			return nil, errutil.Wrapf(err, "decoding user handle")
		}
	}

	// Wrap it in the spec type
	return &spec.AuthenticatorAssertionResponse{
		AuthData:       authenticatorDataBytes,
		ClientDataJSON: clientDataJSONBytes,
		Signature:      signatureBytes,
		UserHandle:     userHandleBytes,
	}, nil
}
