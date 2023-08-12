package webauthn_test

import (
	"github.com/spiretechnology/go-webauthn"
	"github.com/spiretechnology/go-webauthn/internal/mocks"
	"github.com/spiretechnology/go-webauthn/internal/testutil"
	"github.com/spiretechnology/go-webauthn/pkg/challenge"
)

func setupMocks(tc testutil.TestCase, challengeFunc func() challenge.Challenge) (webauthn.WebAuthn, *mocks.MockCredentials, *mocks.MockTokener) {
	credentials := &mocks.MockCredentials{}
	tokener := &mocks.MockTokener{}

	var options webauthn.Options
	options.RP = tc.RelyingParty
	options.Credentials = credentials
	options.Tokener = tokener
	if challengeFunc != nil {
		options.ChallengeFunc = func() (challenge.Challenge, error) {
			return challengeFunc(), nil
		}
	}

	w := webauthn.New(options)
	return w, credentials, tokener
}
