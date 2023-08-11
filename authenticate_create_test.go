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

func TestCreateAuthentication(t *testing.T) {
	ctx := context.Background()
	for _, tc := range testCases {
		tcChallenge := tc.AuthenticationChallenge()

		t.Run(tc.Name, func(t *testing.T) {
			t.Run("user has no credentials", func(t *testing.T) {
				w, credentials, challenges := setupMocks(nil)
				credentials.On("GetCredentials", ctx, tc.User).Return([]webauthn.Credential{}, nil).Once()

				challenge, err := w.CreateAuthentication(ctx, tc.User)
				require.Nil(t, challenge, "challenge should be nil")
				require.ErrorIs(t, err, webauthn.ErrNoCredentials, "error should be ErrNoCredentials")

				credentials.AssertExpectations(t)
				challenges.AssertExpectations(t)
			})

			t.Run("storing challenge fails", func(t *testing.T) {
				w, credentials, challenges := setupMocks(nil)
				credentials.On("GetCredentials", ctx, tc.User).Return([]webauthn.Credential{*tc.Credential()}, nil).Once()
				challenges.On("StoreChallenge", mock.Anything, tc.User, mock.Anything).Return(errors.New("test error")).Once()

				challenge, err := w.CreateAuthentication(ctx, tc.User)
				require.Nil(t, challenge, "challenge should be nil")
				require.Error(t, err, "error should not be nil")

				credentials.AssertExpectations(t)
				challenges.AssertExpectations(t)
			})

			t.Run("creates authentication successfully", func(t *testing.T) {
				w, credentials, challenges := setupMocks(&webauthn.Options{
					ChallengeFunc: func() (webauthn.Challenge, error) {
						return tcChallenge, nil
					},
				})
				credentials.On("GetCredentials", ctx, tc.User).Return([]webauthn.Credential{*tc.Credential()}, nil).Once()
				challenges.On("StoreChallenge", mock.Anything, tc.User, mock.Anything).Return(nil).Once()

				challenge, err := w.CreateAuthentication(ctx, tc.User)
				require.NotNil(t, challenge, "challenge should not be nil")
				require.Nil(t, err, "error should be nil")

				require.Equal(t, testutil.Encode(tcChallenge[:]), challenge.Challenge, "challenge should match")
				require.Equal(t, testRP.ID, challenge.RPID, "relying party should match")
				require.Equal(t, 1, len(challenge.AllowCredentials), "allow credentials should match")

				credentials.AssertExpectations(t)
				challenges.AssertExpectations(t)
			})
		})
	}
}
