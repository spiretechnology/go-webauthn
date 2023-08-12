package webauthn_test

import (
	"context"
	"testing"

	"github.com/spiretechnology/go-webauthn"
	"github.com/spiretechnology/go-webauthn/internal/mocks"
	"github.com/spiretechnology/go-webauthn/internal/testutil"
	"github.com/spiretechnology/go-webauthn/pkg/challenge"
	"github.com/spiretechnology/go-webauthn/pkg/errs"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func seedMockWithCredential(t *testing.T, tc testutil.TestCase, w webauthn.WebAuthn, credentials *mocks.MockCredentials, challenges *mocks.MockChallenges) webauthn.Credential {
	// Seed the store with a valid credential
	challenges.On("HasChallenge", mock.Anything, tc.User, tc.RegistrationChallenge()).Return(true, nil).Once()
	challenges.On("RemoveChallenge", mock.Anything, tc.User, tc.RegistrationChallenge()).Return(nil).Once()
	credentials.On("StoreCredential", mock.Anything, tc.User, mock.Anything, mock.Anything).Return(nil).Once()
	reg, err := w.VerifyRegistration(context.Background(), tc.User, &tc.Registration)
	require.NoError(t, err, "seeding credential should not error")
	return reg.Credential
}

func TestVerifyAuthentication(t *testing.T) {
	ctx := context.Background()
	for _, tc := range testutil.TestCases {
		tcChallenge := tc.AuthenticationChallenge()

		t.Run(tc.Name, func(t *testing.T) {
			t.Run("challenge doesn't exist", func(t *testing.T) {
				w, credentials, challenges := setupMocks(tc, nil)
				challenges.On("HasChallenge", mock.Anything, tc.User, tcChallenge).Return(false, nil).Once()

				result, err := w.VerifyAuthentication(ctx, tc.User, &tc.Authentication)
				require.Nil(t, result, "result should be nil")
				require.ErrorIs(t, err, errs.ErrUnrecognizedChallenge, "error should be errTest")

				credentials.AssertExpectations(t)
				challenges.AssertExpectations(t)
			})

			t.Run("verifies registration successfully", func(t *testing.T) {
				w, credentials, challenges := setupMocks(tc, &webauthn.Options{
					ChallengeFunc: func() (challenge.Challenge, error) {
						return tcChallenge, nil
					},
				})

				// Seed the store with a valid credential
				credential := seedMockWithCredential(t, tc, w, credentials, challenges)

				challenges.On("HasChallenge", mock.Anything, tc.User, tcChallenge).Return(true, nil).Once()
				challenges.On("RemoveChallenge", mock.Anything, tc.User, tcChallenge).Return(nil).Once()
				credentials.On("GetCredential", mock.Anything, tc.User, mock.Anything).Return(&credential, nil).Once()

				result, err := w.VerifyAuthentication(ctx, tc.User, &tc.Authentication)
				require.Nil(t, err, "error should be nil")
				require.NotNil(t, result, "result should not be nil")

				credentials.AssertExpectations(t)
				challenges.AssertExpectations(t)
			})
		})
	}
}
