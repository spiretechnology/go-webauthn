package webauthn_test

import (
	"context"
	"testing"

	"github.com/spiretechnology/go-webauthn"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestVerifyRegistration(t *testing.T) {
	ctx := context.Background()
	for _, tc := range testCases {
		tcChallenge := tc.RegistrationChallenge()

		t.Run(tc.Name, func(t *testing.T) {
			t.Run("user does not exist", func(t *testing.T) {
				w, users, _, challenges := setupMocks(nil)
				challenges.On("HasChallenge", mock.Anything, tc.User.ID, tcChallenge).Return(true, nil).Once()
				challenges.On("RemoveChallenge", mock.Anything, tc.User.ID, tcChallenge).Return(nil).Once()
				users.On("GetUser", ctx, tc.User.ID).Return(nil, nil).Once()

				result, err := w.VerifyRegistration(ctx, tc.User.ID, tc.RegistrationResponse())
				require.Nil(t, result, "result should be nil")
				require.ErrorIs(t, err, webauthn.ErrUserNotFound, "error should be ErrUserNotFound")

				users.AssertExpectations(t)
				challenges.AssertExpectations(t)
			})

			t.Run("challenge doesn't exist", func(t *testing.T) {
				w, users, _, challenges := setupMocks(nil)
				challenges.On("HasChallenge", mock.Anything, tc.User.ID, tcChallenge).Return(false, nil).Once()

				result, err := w.VerifyRegistration(ctx, tc.User.ID, tc.RegistrationResponse())
				require.Nil(t, result, "result should be nil")
				require.ErrorIs(t, err, webauthn.ErrUnrecognizedChallenge, "error should be errTest")

				users.AssertExpectations(t)
				challenges.AssertExpectations(t)
			})

			t.Run("verifies registration successfully", func(t *testing.T) {
				w, users, credentials, challenges := setupMocks(&webauthn.Options{
					ChallengeFunc: func() ([32]byte, error) {
						return tcChallenge, nil
					},
				})
				challenges.On("HasChallenge", mock.Anything, tc.User.ID, tcChallenge).Return(true, nil).Once()
				challenges.On("RemoveChallenge", mock.Anything, tc.User.ID, tcChallenge).Return(nil).Once()
				users.On("GetUser", ctx, tc.User.ID).Return(&tc.User, nil).Once()
				credentials.On("StoreCredential", mock.Anything, tc.User.ID, mock.Anything).Return(nil).Once()

				result, err := w.VerifyRegistration(ctx, tc.User.ID, tc.RegistrationResponse())
				require.Nil(t, err, "error should be nil")
				require.NotNil(t, result, "result should not be nil")

				users.AssertExpectations(t)
				challenges.AssertExpectations(t)
				credentials.AssertExpectations(t)
			})

			t.Run("fails with invalid public key alg", func(t *testing.T) {
				w, users, credentials, challenges := setupMocks(&webauthn.Options{
					ChallengeFunc: func() ([32]byte, error) {
						return tcChallenge, nil
					},
				})
				challenges.On("HasChallenge", mock.Anything, tc.User.ID, tcChallenge).Return(true, nil).Once()
				challenges.On("RemoveChallenge", mock.Anything, tc.User.ID, tcChallenge).Return(nil).Once()
				users.On("GetUser", ctx, tc.User.ID).Return(&tc.User, nil).Once()

				// Switch to an unsupported public key alg
				res := tc.RegistrationResponse()
				res.PublicKeyAlg = 0

				result, err := w.VerifyRegistration(ctx, tc.User.ID, res)
				require.Nil(t, result, "result should be nil")
				require.Error(t, err, "error should not be nil")

				users.AssertExpectations(t)
				challenges.AssertExpectations(t)
				credentials.AssertExpectations(t)
			})
		})
	}
}
