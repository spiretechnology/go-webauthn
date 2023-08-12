package webauthn_test

import (
	"context"
	"errors"
	"testing"

	"github.com/spiretechnology/go-webauthn"
	"github.com/spiretechnology/go-webauthn/internal/mocks"
	"github.com/spiretechnology/go-webauthn/internal/testutil"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func seedMockWithCredential(t *testing.T, tc testutil.TestCase, w webauthn.WebAuthn, credentials *mocks.MockCredentials, tokener *mocks.MockTokener) webauthn.Credential {
	// Seed the store with a valid credential
	tokener.On("VerifyToken", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
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
			t.Run("challenge token is invalid", func(t *testing.T) {
				w, credentials, tokener := setupMocks(tc, tc.AuthenticationChallenge)
				tokener.On("VerifyToken", tc.Authentication.Token, tcChallenge, tc.User).Return(errors.New("invalid token")).Once()

				result, err := w.VerifyAuthentication(ctx, tc.User, &tc.Authentication)
				require.Nil(t, result, "result should be nil")
				require.Error(t, err, "verify authentication should error")

				credentials.AssertExpectations(t)
				tokener.AssertExpectations(t)
			})

			t.Run("verifies registration successfully", func(t *testing.T) {
				w, credentials, tokener := setupMocks(tc, tc.AuthenticationChallenge)

				// Seed the store with a valid credential
				credential := seedMockWithCredential(t, tc, w, credentials, tokener)

				tokener.On("VerifyToken", tc.Authentication.Token, tcChallenge, tc.User).Return(nil).Once()
				credentials.On("GetCredential", mock.Anything, tc.User, mock.Anything).Return(&credential, nil).Once()

				result, err := w.VerifyAuthentication(ctx, tc.User, &tc.Authentication)
				require.Nil(t, err, "error should be nil")
				require.NotNil(t, result, "result should not be nil")
				require.Equal(t, credential, result.Credential, "credential should match")

				credentials.AssertExpectations(t)
				tokener.AssertExpectations(t)
			})
		})
	}
}
