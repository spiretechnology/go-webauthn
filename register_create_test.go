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
			t.Run("user does not exist", func(t *testing.T) {
				w, users, _, challenges := setupMocks(nil)
				users.On("GetUser", ctx, tc.User.ID).Return(nil, nil).Once()

				challenge, err := w.CreateRegistration(ctx, tc.User.ID)
				require.Nil(t, challenge, "challenge should be nil")
				require.ErrorIs(t, err, webauthn.ErrUserNotFound, "error should be ErrUserNotFound")

				users.AssertExpectations(t)
				challenges.AssertNotCalled(t, "StoreChallenge", mock.Anything, mock.Anything, mock.Anything)
			})

			t.Run("storing challenge fails", func(t *testing.T) {
				w, users, _, challenges := setupMocks(nil)
				users.On("GetUser", ctx, tc.User.ID).Return(&tc.User, nil).Once()
				challenges.On("StoreChallenge", mock.Anything, tc.User.ID, mock.Anything).Return(errors.New("test error")).Once()

				challenge, err := w.CreateRegistration(ctx, tc.User.ID)
				require.Nil(t, challenge, "challenge should be nil")
				require.Error(t, err, "error should not be nil")

				users.AssertExpectations(t)
				challenges.AssertExpectations(t)
			})

			t.Run("creates registration successfully", func(t *testing.T) {
				w, users, _, challenges := setupMocks(&webauthn.Options{
					ChallengeFunc: func() ([32]byte, error) {
						return tcChallenge, nil
					},
				})
				users.On("GetUser", ctx, tc.User.ID).Return(&tc.User, nil).Once()
				challenges.On("StoreChallenge", mock.Anything, tc.User.ID, mock.Anything).Return(nil).Once()

				challenge, err := w.CreateRegistration(ctx, tc.User.ID)
				require.NotNil(t, challenge, "challenge should not be nil")
				require.Nil(t, err, "error should be nil")

				require.Equal(t, testutil.Encode(tcChallenge[:]), challenge.Challenge, "challenge should match")
				require.Equal(t, testRP, challenge.RP, "relying party should match")
				require.Equal(t, tc.User.ID, challenge.User.ID, "user id should match")
				require.Equal(t, tc.User.Name, challenge.User.Name, "user name should match")
				require.Equal(t, tc.User.DisplayName, challenge.User.DisplayName, "user display name should match")
				require.Equal(t, 6, len(challenge.PubKeyCredParams), "pub key cred params should match")

				users.AssertExpectations(t)
				challenges.AssertExpectations(t)
			})
		})
	}
}
