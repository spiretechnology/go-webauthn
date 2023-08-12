package webauthn_test

import (
	"github.com/spiretechnology/go-webauthn"
	"github.com/spiretechnology/go-webauthn/internal/mocks"
	"github.com/spiretechnology/go-webauthn/internal/testutil"
)

func setupMocks(tc testutil.TestCase, opts *webauthn.Options) (webauthn.WebAuthn, *mocks.MockCredentials, *mocks.MockChallenges) {
	credentials := &mocks.MockCredentials{}
	challenges := &mocks.MockChallenges{}

	var options webauthn.Options
	if opts != nil {
		options = *opts
	}
	options.RP = tc.RelyingParty
	options.Credentials = credentials
	options.Challenges = challenges

	w := webauthn.New(options)

	return w, credentials, challenges
}
