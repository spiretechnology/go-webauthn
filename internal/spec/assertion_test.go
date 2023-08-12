package spec_test

import (
	"crypto/sha256"
	"testing"

	"github.com/spiretechnology/go-webauthn/internal/spec"
	"github.com/spiretechnology/go-webauthn/internal/testutil"
	"github.com/spiretechnology/go-webauthn/pkg/challenge"
	"github.com/stretchr/testify/require"
)

func TestAssertion(t *testing.T) {
	for _, tc := range testutil.TestCases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Run("decode cbor", func(t *testing.T) {
				res := spec.AuthenticatorAssertionResponse{
					AuthData:       testutil.Decode(tc.Authentication.Response.AuthenticatorData),
					ClientDataJSON: testutil.Decode(tc.Authentication.Response.ClientDataJSON),
					Signature:      testutil.Decode(tc.Authentication.Response.Signature),
				}
				if tc.Authentication.Response.UserHandle != nil {
					res.UserHandle = testutil.Decode(*tc.Authentication.Response.UserHandle)
				}

				clientData, err := res.ClientData()
				require.NoError(t, err, "decode client data should not error")
				require.NotNil(t, clientData, "client data should not be nil")
				require.Equal(t, spec.ClientDataTypeGet, clientData.Type, "client data type should be webauthn.get")

				rawChallenge, err := clientData.DecodeChallenge()
				require.NoError(t, err, "decode challenge should not error")
				require.Equal(t, challenge.Challenge(testutil.Decode(tc.Authentication.Challenge)), rawChallenge, "challenge should match")

				authData, err := res.AuthenticatorData()
				require.NoError(t, err, "decode auth data should not error")
				require.NotNil(t, authData, "auth data should not be nil")

				require.Equal(t, sha256.Sum256([]byte(tc.RelyingParty.ID)), authData.RPIDHash, "rp id hash should match")
				require.Equal(t, testutil.ParseFlags(tc.Assertion.Flags), authData.Flags, "flags should match")
				require.Equal(t, tc.Assertion.SignCount, authData.SignCount, "sign count should match")
				// require.Equal(t, tc.Attestation.AAGUIDHex, hex.EncodeToString(authData.AttestedCredential.AAGUID[:]), "aaguid should match")
				// require.Equal(t, tc.Attestation.CredIDHex, hex.EncodeToString(authData.AttestedCredential.CredID), "cred id should match")
				// require.Equal(t, testutil.Decode(tc.Attestation.CredPublicKeyB64), authData.AttestedCredential.CredPublicKey, "cred public key should match")

				// fmt.Println("AAGUID: ", hex.EncodeToString(authData.AttestedCredential.AAGUID[:]))
				// fmt.Println("CredID: ", hex.EncodeToString(authData.AttestedCredential.CredID))
				// fmt.Println("CredPublicKey: ", base64.RawURLEncoding.EncodeToString(authData.AttestedCredential.CredPublicKey))

				// fmt.Printf("%+v\n", authData.AttestedCredential)
			})
		})
	}
}
