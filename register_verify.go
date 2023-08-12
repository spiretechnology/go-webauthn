package webauthn

import (
	"context"
	"crypto/sha256"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/pkg/authenticators"
	"github.com/spiretechnology/go-webauthn/pkg/challenge"
	"github.com/spiretechnology/go-webauthn/pkg/errs"
	"github.com/spiretechnology/go-webauthn/pkg/pubkey"
	"github.com/spiretechnology/go-webauthn/pkg/spec"
	"golang.org/x/exp/slices"
)

// RegistrationResponse is the response sent back by the client after a registration ceremony.
type RegistrationResponse struct {
	Challenge    string                           `json:"challenge"`
	CredentialID string                           `json:"credentialId"`
	Response     AuthenticatorAttestationResponse `json:"response"`
}

// RegistrationResult contains the results of verifying the registration respose.
type RegistrationResult struct {
	Credential Credential
}

func (w *webauthn) VerifyRegistration(ctx context.Context, user User, res *RegistrationResponse) (*RegistrationResult, error) {
	// Decode the challenge from the response
	challengeBytesSlice, err := w.options.Codec.DecodeString(res.Challenge)
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding challenge")
	}
	if len(challengeBytesSlice) != challenge.ChallengeSize {
		return nil, errutil.Wrap(errs.ErrInvalidChallenge)
	}
	challengeBytes := challenge.Challenge(challengeBytesSlice)
	ok, err := w.options.Challenges.HasChallenge(ctx, user, challengeBytes)
	if err != nil {
		return nil, errutil.Wrapf(err, "checking challenge")
	}
	if !ok {
		return nil, errutil.Wrap(errs.ErrUnrecognizedChallenge)
	}

	// Remove the challenge from the store. It's no longer needed.
	if err := w.options.Challenges.RemoveChallenge(ctx, user, challengeBytes); err != nil {
		return nil, errutil.Wrapf(err, "removing challenge")
	}

	// Decode the attestation response to spec types
	attestationResponse, err := res.Response.Decode(w.options.Codec)
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding attestation response")
	}

	//================================================================================
	// Validate the client data
	//================================================================================

	// Decode the clientDataJSON
	clientData, err := attestationResponse.ClientData()
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding client data")
	}

	// Verify that the decoded clientDataJSON.type is "webauthn.create"
	if clientData.Type != spec.ClientDataTypeCreate {
		return nil, errutil.Wrapf(err, "invalid client data type %q", clientData.Type)
	}

	// Verify that this challenge was issued to the client
	clientDataChallengeBytes, err := clientData.DecodeChallenge()
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding challenge")
	}
	if clientDataChallengeBytes != challengeBytes {
		return nil, errutil.Wrapf(err, "invalid challenge")
	}

	//================================================================================
	// Validate the attestation object
	//================================================================================

	// Decode the attestationObject
	attestationObject, err := attestationResponse.AttestationObject()
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding attestation object")
	}

	// Decode the the auth data within the attestation
	authData, err := attestationObject.AuthenticatorData()
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding auth data")
	}

	// Verify that the rpIdHash is the SHA-256 hash of the Relying Party ID
	if authData.RPIDHash != sha256.Sum256([]byte(w.options.RP.ID)) {
		return nil, errutil.Wrapf(err, "invalid RP ID hash")
	}

	//================================================================================
	// Decode and validate the public key
	//================================================================================

	// Check if there is an attested credential
	if authData.AttestedCredential == nil {
		return nil, errutil.New("no attested credential")
	}

	// Check if the public key alg is supported
	if !slices.Contains(w.options.PublicKeyTypes, authData.AttestedCredential.CredPublicKeyType) {
		return nil, errutil.Wrap(errs.ErrUnsupportedPublicKey)
	}

	// Verify the signature of the response
	if err := attestationResponse.Verify(); err != nil {
		return nil, errutil.Wrapf(err, "verifying signature")
	}

	//================================================================================
	// Store the credential and return successfully
	//================================================================================

	// Decode the credential ID
	credentialIDBytes, err := w.options.Codec.DecodeString(res.CredentialID)
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding credential ID")
	}

	// Encode the public key to DER bytes for storage
	publicKeyBytes, err := pubkey.Encode(authData.AttestedCredential.CredPublicKey)
	if err != nil {
		return nil, errutil.Wrapf(err, "encoding public key")
	}

	// Store the credential for the user
	cred := Credential{
		ID:           credentialIDBytes,
		Type:         "public-key",
		PublicKey:    publicKeyBytes,
		PublicKeyAlg: int(authData.AttestedCredential.CredPublicKeyType),
	}
	meta := CredentialMeta{
		Authenticator: authenticators.LookupAuthenticator(authData.AttestedCredential.AAGUID),
	}
	if err := w.options.Credentials.StoreCredential(ctx, user, cred, meta); err != nil {
		return nil, errutil.Wrapf(err, "storing credential")
	}

	// Return the credential
	return &RegistrationResult{
		Credential: cred,
	}, nil
}
