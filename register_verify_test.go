package webauthn_test

import (
	"context"
	"errors"
	"testing"

	"github.com/spiretechnology/go-webauthn/internal/testutil"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestVerifyRegistration(t *testing.T) {
	ctx := context.Background()
	for _, tc := range testutil.TestCases {
		tcChallenge := tc.RegistrationChallenge()

		t.Run(tc.Name, func(t *testing.T) {
			t.Run("challenge token is invalid", func(t *testing.T) {
				w, credentials, tokener := setupMocks(tc, tc.RegistrationChallenge)
				tokener.On("VerifyToken", tc.Registration.Token, tcChallenge, tc.User).Return(errors.New("invalid token")).Once()

				result, err := w.VerifyRegistration(ctx, tc.User, &tc.Registration)
				require.Nil(t, result, "result should be nil")
				require.Error(t, err, "verify registration should error")

				credentials.AssertExpectations(t)
				tokener.AssertExpectations(t)
			})

			t.Run("verifies registration successfully", func(t *testing.T) {
				w, credentials, tokener := setupMocks(tc, tc.RegistrationChallenge)
				tokener.On("VerifyToken", tc.Registration.Token, tcChallenge, tc.User).Return(nil).Once()
				credentials.On("StoreCredential", mock.Anything, tc.User, mock.Anything, mock.Anything).Return(nil).Once()

				result, err := w.VerifyRegistration(ctx, tc.User, &tc.Registration)
				require.Nil(t, err, "error should be nil")
				require.NotNil(t, result, "result should not be nil")

				credentials.AssertExpectations(t)
				tokener.AssertExpectations(t)
			})
		})
	}
}
