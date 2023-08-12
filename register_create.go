package webauthn

import (
	"context"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/pkg/spec"
)

// RegistrationChallenge is the challenge that is sent to the client to initiate a registration ceremony.
type RegistrationChallenge struct {
	Challenge        string                 `json:"challenge"`
	RP               RelyingParty           `json:"rp"`
	User             User                   `json:"user"`
	PubKeyCredParams []spec.PubKeyCredParam `json:"pubKeyCredParams"`
}

func (w *webauthn) CreateRegistration(ctx context.Context, user User) (*RegistrationChallenge, error) {
	// Generate the random challenge
	challengeBytes, err := w.options.ChallengeFunc()
	if err != nil {
		return nil, errutil.Wrapf(err, "generating challenge")
	}

	// Store the challenge in the challenge store
	if err := w.options.Challenges.StoreChallenge(ctx, user, challengeBytes); err != nil {
		return nil, errutil.Wrapf(err, "storing challenge")
	}

	// Format the public key credential params for the client
	pubKeyCredParams := make([]spec.PubKeyCredParam, len(w.options.PublicKeyTypes))
	for i, keyType := range w.options.PublicKeyTypes {
		pubKeyCredParams[i] = spec.PubKeyCredParam{
			Type: "public-key",
			Alg:  int(keyType),
		}
	}

	return &RegistrationChallenge{
		Challenge:        w.options.Codec.EncodeToString(challengeBytes[:]),
		RP:               w.options.RP,
		User:             user,
		PubKeyCredParams: pubKeyCredParams,
	}, nil
}
