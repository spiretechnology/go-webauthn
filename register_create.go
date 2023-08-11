package webauthn

import (
	"context"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/spec"
)

type RegistrationUser struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type RegistrationChallenge struct {
	Challenge        string                 `json:"challenge"`
	RP               spec.RelyingParty      `json:"rp"`
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

	return &RegistrationChallenge{
		Challenge:        w.options.Codec.EncodeToString(challengeBytes[:]),
		RP:               w.options.RP,
		User:             user,
		PubKeyCredParams: w.getPubKeyCredParams(),
	}, nil
}
