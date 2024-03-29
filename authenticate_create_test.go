package webauthn_test

import (
	"context"
	"errors"
	"testing"

	"github.com/spiretechnology/go-webauthn"
	"github.com/spiretechnology/go-webauthn/internal/testutil"
	"github.com/spiretechnology/go-webauthn/pkg/errs"
	"github.com/stretchr/testify/require"
)

func TestCreateAuthentication(t *testing.T) {
	ctx := context.Background()
	testCred := webauthn.Credential{}

	for _, tc := range testutil.TestCases {
		tcChallenge := tc.AuthenticationChallenge()

		t.Run(tc.Name, func(t *testing.T) {
			t.Run("user has no credentials", func(t *testing.T) {
				w, credentials, tokener := setupMocks(tc, tc.AuthenticationChallenge)
				credentials.On("GetCredentials", ctx, tc.User).Return([]webauthn.Credential{}, nil).Once()

				challenge, err := w.CreateAuthentication(ctx, tc.User)
				require.Nil(t, challenge, "challenge should be nil")
				require.ErrorIs(t, err, errs.ErrNoCredentials, "error should be ErrNoCredentials")

				credentials.AssertExpectations(t)
				tokener.AssertExpectations(t)
			})

			t.Run("creating challenge token fails", func(t *testing.T) {
				w, credentials, tokener := setupMocks(tc, tc.AuthenticationChallenge)
				credentials.On("GetCredentials", ctx, tc.User).Return([]webauthn.Credential{testCred}, nil).Once()
				tokener.On("CreateToken", tcChallenge, tc.User).Return("", errors.New("token creation failed")).Once()

				challenge, err := w.CreateAuthentication(ctx, tc.User)
				require.Nil(t, challenge, "challenge should be nil")
				require.Error(t, err, "error should not be nil")

				credentials.AssertExpectations(t)
				tokener.AssertExpectations(t)
			})

			t.Run("creates authentication successfully", func(t *testing.T) {
				w, credentials, tokener := setupMocks(tc, tc.AuthenticationChallenge)
				credentials.On("GetCredentials", ctx, tc.User).Return([]webauthn.Credential{testCred}, nil).Once()
				tokener.On("CreateToken", tcChallenge, tc.User).Return(tc.Authentication.Token, nil).Once()

				challenge, err := w.CreateAuthentication(ctx, tc.User)
				require.NotNil(t, challenge, "challenge should not be nil")
				require.Nil(t, err, "error should be nil")

				require.Equal(t, tc.Authentication.Token, challenge.Token, "token should match")
				require.Equal(t, testutil.Encode(tcChallenge[:]), challenge.Challenge, "challenge should match")
				require.Equal(t, tc.RelyingParty.ID, challenge.RPID, "relying party should match")
				require.Equal(t, 1, len(challenge.AllowCredentials), "allow credentials should match")

				credentials.AssertExpectations(t)
				tokener.AssertExpectations(t)
			})
		})
	}
}
