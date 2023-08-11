package webauthn_test

import (
	"context"
	"errors"
	"testing"

	"github.com/spiretechnology/go-webauthn"
	"github.com/spiretechnology/go-webauthn/internal/testutil"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCreateRegistration(t *testing.T) {
	ctx := context.Background()
	for _, tc := range testCases {
		tcChallenge := tc.RegistrationChallenge()

		t.Run(tc.Name, func(t *testing.T) {
			t.Run("storing challenge fails", func(t *testing.T) {
				w, credentials, challenges := setupMocks(nil)
				challenges.On("StoreChallenge", mock.Anything, tc.User, mock.Anything).Return(errors.New("test error")).Once()

				challenge, err := w.CreateRegistration(ctx, tc.User)
				require.Nil(t, challenge, "challenge should be nil")
				require.Error(t, err, "error should not be nil")

				credentials.AssertExpectations(t)
				challenges.AssertExpectations(t)
			})

			t.Run("creates registration successfully", func(t *testing.T) {
				w, credentials, challenges := setupMocks(&webauthn.Options{
					ChallengeFunc: func() ([32]byte, error) {
						return tcChallenge, nil
					},
				})
				challenges.On("StoreChallenge", mock.Anything, tc.User, mock.Anything).Return(nil).Once()

				challenge, err := w.CreateRegistration(ctx, tc.User)
				require.NotNil(t, challenge, "challenge should not be nil")
				require.Nil(t, err, "error should be nil")

				require.Equal(t, testutil.Encode(tcChallenge[:]), challenge.Challenge, "challenge should match")
				require.Equal(t, testRP, challenge.RP, "relying party should match")
				require.Equal(t, tc.User.ID, challenge.User.ID, "user id should match")
				require.Equal(t, tc.User.Name, challenge.User.Name, "user name should match")
				require.Equal(t, tc.User.DisplayName, challenge.User.DisplayName, "user display name should match")
				require.Equal(t, 6, len(challenge.PubKeyCredParams), "pub key cred params should match")

				credentials.AssertExpectations(t)
				challenges.AssertExpectations(t)
			})
		})
	}
}
