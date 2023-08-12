package webauthn_test

import (
	"context"
	"errors"
	"testing"

	"github.com/spiretechnology/go-webauthn/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestCreateRegistration(t *testing.T) {
	ctx := context.Background()
	for _, tc := range testutil.TestCases {
		tcChallenge := tc.RegistrationChallenge()

		t.Run(tc.Name, func(t *testing.T) {
			t.Run("creating challenge token fails", func(t *testing.T) {
				w, credentials, tokener := setupMocks(tc, tc.RegistrationChallenge)
				tokener.On("CreateToken", tcChallenge, tc.User).Return("", errors.New("test error")).Once()

				challenge, err := w.CreateRegistration(ctx, tc.User)
				require.Nil(t, challenge, "challenge should be nil")
				require.Error(t, err, "error should not be nil")

				credentials.AssertExpectations(t)
				tokener.AssertExpectations(t)
			})

			t.Run("creates registration successfully", func(t *testing.T) {
				w, credentials, tokener := setupMocks(tc, tc.RegistrationChallenge)
				tokener.On("CreateToken", tcChallenge, tc.User).Return(tc.Registration.Token, nil).Once()

				challenge, err := w.CreateRegistration(ctx, tc.User)
				require.NotNil(t, challenge, "challenge should not be nil")
				require.Nil(t, err, "error should be nil")

				require.Equal(t, tc.Registration.Token, challenge.Token, "token should match")
				require.Equal(t, testutil.Encode(tcChallenge[:]), challenge.Challenge, "challenge should match")
				require.Equal(t, tc.RelyingParty, challenge.RP, "relying party should match")
				require.Equal(t, tc.User.ID, challenge.User.ID, "user id should match")
				require.Equal(t, tc.User.Name, challenge.User.Name, "user name should match")
				require.Equal(t, tc.User.DisplayName, challenge.User.DisplayName, "user display name should match")
				require.Equal(t, 9, len(challenge.PubKeyCredParams), "pub key cred params should match")

				credentials.AssertExpectations(t)
				tokener.AssertExpectations(t)
			})
		})
	}
}
