package webauthn

import (
	"context"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
)

type AuthenticationChallenge struct {
	Challenge        string              `json:"challenge"`
	RPID             string              `json:"rpId"`
	AllowCredentials []AllowedCredential `json:"allowCredentials"`
}

type AllowedCredential struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (w *webauthn) CreateAuthentication(ctx context.Context, userID string) (*AuthenticationChallenge, error) {
	// Get all credentials for the user
	credentials, err := w.options.Credentials.GetCredentials(ctx, userID)
	if err != nil {
		return nil, errutil.Wrapf(err, "getting credentials")
	}

	// Generate the random challenge
	challengeBytes, err := w.options.ChallengeFunc()
	if err != nil {
		return nil, errutil.Wrapf(err, "generating challenge")
	}

	// Store the challenge in the challenge store
	if err := w.options.Challenges.StoreChallenge(ctx, userID, challengeBytes); err != nil {
		return nil, errutil.Wrapf(err, "storing challenge")
	}

	// Format the response
	var res AuthenticationChallenge
	res.Challenge = w.options.Codec.EncodeToString(challengeBytes[:])
	res.RPID = w.options.RP.ID
	for _, cred := range credentials {
		res.AllowCredentials = append(res.AllowCredentials, AllowedCredential{
			Type: cred.Type,
			ID:   w.options.Codec.EncodeToString(cred.ID),
		})
	}
	return &res, nil
}
