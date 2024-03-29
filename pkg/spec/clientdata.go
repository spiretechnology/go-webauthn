package spec

import (
	"encoding/base64"
	"errors"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/pkg/challenge"
)

const (
	// ClientDataTypeCreate is the type of a client data for a registration.
	ClientDataTypeCreate = "webauthn.create"

	// ClientDataTypeGet is the type of a client data for an authentication.
	ClientDataTypeGet = "webauthn.get"
)

type ClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin *bool  `json:"crossOrigin,omitempty"`
	// TokenBinding *TokenBinding `json:"tokenBinding,omitempty"`
}

func (c *ClientData) DecodeChallenge() (challenge.Challenge, error) {
	challengeBytes, err := base64.RawURLEncoding.DecodeString(c.Challenge)
	if err != nil {
		return challenge.Challenge{}, errutil.Wrapf(err, "decoding challenge")
	}
	if len(challengeBytes) != 32 {
		return challenge.Challenge{}, errutil.Wrap(errors.New("challenge must be 32 bytes"))
	}
	var chal challenge.Challenge
	copy(chal[:], challengeBytes)
	return chal, nil
}
