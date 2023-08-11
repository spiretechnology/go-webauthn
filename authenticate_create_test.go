package webauthn_test

import (
	"context"
	"errors"
	"testing"

	"github.com/spiretechnology/go-webauthn"
	"github.com/spiretechnology/go-webauthn/internal/testutil"
	"github.com/spiretechnology/go-webauthn/store"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCreateAuthentication(t *testing.T) {
	ctx := context.Background()
	for _, tc := range testCases {
		tcChallenge := tc.AuthenticationChallenge()

		t.Run(tc.Name, func(t *testing.T) {
			t.Run("user has no credentials", func(t *testing.T) {
				w, users, credentials, challenges := setupMocks(nil)
				credentials.On("GetCredentials", ctx, tc.User.ID).Return([]store.Credential{}, nil).Once()

				challenge, err := w.CreateAuthentication(ctx, tc.User.ID)
				require.Nil(t, challenge, "challenge should be nil")
				require.ErrorIs(t, err, webauthn.ErrNoCredentials, "error should be ErrNoCredentials")

				users.AssertExpectations(t)
				credentials.AssertExpectations(t)
				challenges.AssertExpectations(t)
			})

			t.Run("storing challenge fails", func(t *testing.T) {
				w, users, credentials, challenges := setupMocks(nil)
				credentials.On("GetCredentials", ctx, tc.User.ID).Return([]store.Credential{*tc.Credential()}, nil).Once()
				challenges.On("StoreChallenge", mock.Anything, tc.User.ID, mock.Anything).Return(errors.New("test error")).Once()

				challenge, err := w.CreateAuthentication(ctx, tc.User.ID)
				require.Nil(t, challenge, "challenge should be nil")
				require.Error(t, err, "error should not be nil")

				users.AssertExpectations(t)
				credentials.AssertExpectations(t)
				challenges.AssertExpectations(t)
			})

			t.Run("creates authentication successfully", func(t *testing.T) {
				w, users, credentials, challenges := setupMocks(&webauthn.Options{
					ChallengeFunc: func() ([32]byte, error) {
						return tcChallenge, nil
					},
				})
				credentials.On("GetCredentials", ctx, tc.User.ID).Return([]store.Credential{*tc.Credential()}, nil).Once()
				challenges.On("StoreChallenge", mock.Anything, tc.User.ID, mock.Anything).Return(nil).Once()

				challenge, err := w.CreateAuthentication(ctx, tc.User.ID)
				require.NotNil(t, challenge, "challenge should not be nil")
				require.Nil(t, err, "error should be nil")

				require.Equal(t, testutil.Encode(tcChallenge[:]), challenge.Challenge, "challenge should match")
				require.Equal(t, testRP.ID, challenge.RPID, "relying party should match")
				require.Equal(t, 1, len(challenge.AllowCredentials), "allow credentials should match")

				users.AssertExpectations(t)
				credentials.AssertExpectations(t)
				challenges.AssertExpectations(t)
			})
		})
	}
}
