package webauthn

import (
	"context"
	"crypto/sha256"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/internal/spec"
)

type RegistrationResponse struct {
	Challenge    string                           `json:"challenge"`
	CredentialID string                           `json:"credentialId"`
	Response     AuthenticatorAttestationResponse `json:"response"`
	PublicKey    string                           `json:"publicKey"`
	PublicKeyAlg int                              `json:"publicKeyAlg"`
}

type RegistrationResult struct{}

func (w *webauthn) VerifyRegistration(ctx context.Context, user User, res *RegistrationResponse) (*RegistrationResult, error) {
	// Decode the challenge from the response
	challengeBytesSlice, err := w.options.Codec.DecodeString(res.Challenge)
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding challenge")
	}
	challengeBytes := [32]byte(challengeBytesSlice)
	ok, err := w.options.Challenges.HasChallenge(ctx, user, challengeBytes)
	if err != nil {
		return nil, errutil.Wrapf(err, "checking challenge")
	}
	if !ok {
		return nil, errutil.Wrap(ErrUnrecognizedChallenge)
	}

	// Remove the challenge from the store. It's no longer needed.
	if err := w.options.Challenges.RemoveChallenge(ctx, user, challengeBytes); err != nil {
		return nil, errutil.Wrapf(err, "removing challenge")
	}

	// Check if the public key alg is supported
	if !w.supportsPublicKeyAlg(PublicKeyType(res.PublicKeyAlg)) {
		return nil, errutil.Wrap(ErrUnsupportedPublicKey)
	}

	// Decode the public key into a byte slice
	publicKeyBytes, err := w.options.Codec.DecodeString(res.PublicKey)
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding public key")
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
	clientData, err := attestationResponse.DecodeClientData()
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
	attestationObject, err := attestationResponse.DecodeAttestationObject()
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding attestation object")
	}

	// Decode the the auth data within the attestation
	authData, err := attestationObject.DecodeAuthData()
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding auth data")
	}

	// Verify that the rpIdHash is the SHA-256 hash of the Relying Party ID
	if authData.RPIDHash != sha256.Sum256([]byte(w.options.RP.ID)) {
		return nil, errutil.Wrapf(err, "invalid RP ID hash")
	}

	// Verify that the flags are valid
	// ...

	// Verify that the attested credential data is valid
	// ...

	//================================================================================
	// Store the credential and return successfully
	//================================================================================

	// Decode the credential ID
	credentialIDBytes, err := w.options.Codec.DecodeString(res.CredentialID)
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding credential ID")
	}

	// Store the credential for the user
	cred := Credential{
		ID:           credentialIDBytes,
		Type:         "public-key",
		PublicKey:    publicKeyBytes,
		PublicKeyAlg: res.PublicKeyAlg,
	}
	if err := w.options.Credentials.StoreCredential(ctx, user, cred); err != nil {
		return nil, errutil.Wrapf(err, "storing credential")
	}

	return &RegistrationResult{}, nil
}
