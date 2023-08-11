package webauthn_test

import (
	"context"
	"testing"

	"github.com/spiretechnology/go-webauthn"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestVerifyAuthentication(t *testing.T) {
	ctx := context.Background()
	for _, tc := range testCases {
		tcChallenge := tc.AuthenticationChallenge()

		t.Run(tc.Name, func(t *testing.T) {
			t.Run("challenge doesn't exist", func(t *testing.T) {
				w, users, credentials, challenges := setupMocks(nil)
				challenges.On("HasChallenge", mock.Anything, tc.User.ID, tcChallenge).Return(false, nil).Once()

				result, err := w.VerifyAuthentication(ctx, tc.User.ID, tc.AuthenticationResponse())
				require.Nil(t, result, "result should be nil")
				require.ErrorIs(t, err, webauthn.ErrUnrecognizedChallenge, "error should be errTest")

				users.AssertExpectations(t)
				credentials.AssertExpectations(t)
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
				credentials.On("GetCredential", mock.Anything, tc.User.ID, mock.Anything).Return(tc.Credential(), nil).Once()

				result, err := w.VerifyAuthentication(ctx, tc.User.ID, tc.AuthenticationResponse())
				require.Nil(t, err, "error should be nil")
				require.NotNil(t, result, "result should not be nil")

				users.AssertExpectations(t)
				challenges.AssertExpectations(t)
				credentials.AssertExpectations(t)
			})

			// t.Run("fails with invalid public key alg", func(t *testing.T) {
			// 	w, users, credentials, challenges := setupMocks(&webauthn.Options{
			// 		ChallengeFunc: func() ([32]byte, error) {
			// 			return tcChallenge, nil
			// 		},
			// 	})
			// 	challenges.On("HasChallenge", mock.Anything, tc.User.ID, tcChallenge).Return(true, nil).Once()
			// 	challenges.On("RemoveChallenge", mock.Anything, tc.User.ID, tcChallenge).Return(nil).Once()
			// 	users.On("GetUser", ctx, tc.User.ID).Return(&tc.User, nil).Once()

			// 	// Switch to an unsupported public key alg
			// 	res := tc.AuthenticationResponse()
			// 	res.PublicKeyAlg = 0

			// 	result, err := w.VerifyAuthentication(ctx, tc.User.ID, res)
			// 	require.Nil(t, result, "result should be nil")
			// 	require.Error(t, err, "error should not be nil")

			// 	users.AssertExpectations(t)
			// 	challenges.AssertExpectations(t)
			// 	credentials.AssertExpectations(t)
			// })
		})
	}
}
