package spec_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/spiretechnology/go-webauthn/internal/testutil"
	"github.com/spiretechnology/go-webauthn/pkg/spec"
	"github.com/stretchr/testify/require"
)

func TestAttestationObject(t *testing.T) {
	for _, tc := range testutil.TestCases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Run("decode cbor", func(t *testing.T) {
				res := spec.AuthenticatorAttestationResponse{
					AttestationObjectCBOR: testutil.Decode(tc.Registration.Response.AttestationObject),
				}

				attestationObject, err := res.AttestationObject()
				require.NoError(t, err, "decode attestation object should not error")
				require.NotNil(t, attestationObject, "attestation object should not be nil")
				require.Equal(t, tc.Attestation.Fmt, attestationObject.Fmt, "attestation object fmt should match")

				authData, err := attestationObject.AuthenticatorData()
				require.NoError(t, err, "decode auth data should not error")
				require.NotNil(t, authData, "auth data should not be nil")

				require.Equal(t, sha256.Sum256([]byte(tc.RelyingParty.ID)), authData.RPIDHash, "rp id hash should match")
				require.Equal(t, testutil.ParseFlags(tc.Attestation.Flags), authData.Flags, "flags should match")
				require.Equal(t, tc.Attestation.SignCount, authData.SignCount, "sign count should match")
				require.Equal(t, tc.Attestation.AAGUIDHex, hex.EncodeToString(authData.AttestedCredential.AAGUID[:]), "aaguid should match")
				require.Equal(t, tc.Attestation.CredIDHex, hex.EncodeToString(authData.AttestedCredential.CredID), "cred id should match")

				// fmt.Printf("PublicKey: %T, %v\n", authData.AttestedCredential.CredPublicKey, authData.AttestedCredential.CredPublicKey)
				// encodedPubKey, err := pubkey.Encode(authData.AttestedCredential.CredPublicKey)
				// require.NoError(t, err, "encode cred public key should not error")
				// require.Equal(t, testutil.Decode(tc.Key.PublicKeyB64), encodedPubKey, "cred public key should match")

				err = authData.AttestedCredential.CredPublicKeyType.CheckKey(authData.AttestedCredential.CredPublicKey)
				require.NoError(t, err, "check key should not error")

				// fmt.Println("AAGUID: ", hex.EncodeToString(authData.AttestedCredential.AAGUID[:]))
				// fmt.Println("CredID: ", hex.EncodeToString(authData.AttestedCredential.CredID))
				// fmt.Println("CredPublicKey: ", base64.RawURLEncoding.EncodeToString(authData.AttestedCredential.CredPublicKey))

				// fmt.Printf("%+v\n", authData.AttestedCredential)
			})
		})
	}
}
