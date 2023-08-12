package webauthn

import (
	"context"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/pkg/errs"
)

// AuthenticationChallenge is the challenge that is sent to the client to initiate an authentication ceremony.
type AuthenticationChallenge struct {
	Token            string              `json:"token"`
	Challenge        string              `json:"challenge"`
	RPID             string              `json:"rpId"`
	AllowCredentials []AllowedCredential `json:"allowCredentials"`
}

// AllowedCredential is a credential that is allowed to be used for authentication.
type AllowedCredential struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (w *webauthn) CreateAuthentication(ctx context.Context, user User) (*AuthenticationChallenge, error) {
	// Get all credentials for the user
	credentials, err := w.options.Credentials.GetCredentials(ctx, user)
	if err != nil {
		return nil, errutil.Wrapf(err, "getting credentials")
	}
	if len(credentials) == 0 {
		return nil, errutil.Wrap(errs.ErrNoCredentials)
	}

	// Generate the random challenge
	challengeBytes, err := w.options.ChallengeFunc()
	if err != nil {
		return nil, errutil.Wrapf(err, "generating challenge")
	}

	// Create the token for the challenge
	token, err := w.options.Tokener.CreateToken(challengeBytes, user)
	if err != nil {
		return nil, errutil.Wrapf(err, "creating token")
	}

	// Format the response
	res := AuthenticationChallenge{
		Token:     token,
		Challenge: w.options.Codec.EncodeToString(challengeBytes[:]),
		RPID:      w.options.RP.ID,
	}
	for _, cred := range credentials {
		res.AllowCredentials = append(res.AllowCredentials, AllowedCredential{
			Type: cred.Type,
			ID:   w.options.Codec.EncodeToString(cred.ID),
		})
	}
	return &res, nil
}
