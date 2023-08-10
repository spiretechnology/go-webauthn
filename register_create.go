package webauthn

import (
	"context"

	"github.com/spiretechnology/go-webauthn/internal/challenge"
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
	User             RegistrationUser       `json:"user"`
	PubKeyCredParams []spec.PubKeyCredParam `json:"pubKeyCredParams"`
}

func (w *webauthn) CreateRegistration(ctx context.Context, userID string) (*RegistrationChallenge, error) {
	// Get the user with the given ID
	user, err := w.options.Users.GetUser(ctx, userID)
	if err != nil {
		return nil, errutil.Wrapf(err, "getting user")
	}
	if user == nil {
		return nil, errutil.Wrap(ErrUserNotFound)
	}

	// Format the user
	registrationUser := RegistrationUser{
		ID:          user.ID,
		Name:        user.Name,
		DisplayName: user.DisplayName,
	}

	// Generate the random challenge
	challengeBytes, err := challenge.GenerateChallenge()
	if err != nil {
		return nil, errutil.Wrapf(err, "generating challenge")
	}

	// Store the challenge in the challenge store
	if err := w.options.Challenges.StoreChallenge(ctx, userID, challengeBytes); err != nil {
		return nil, errutil.Wrapf(err, "storing challenge")
	}

	return &RegistrationChallenge{
		Challenge:        w.options.Codec.EncodeToString(challengeBytes[:]),
		RP:               w.options.RP,
		User:             registrationUser,
		PubKeyCredParams: w.getPubKeyCredParams(),
	}, nil
}
