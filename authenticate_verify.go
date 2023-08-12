package webauthn

import (
	"context"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/pkg/challenge"
	"github.com/spiretechnology/go-webauthn/pkg/errs"
	"github.com/spiretechnology/go-webauthn/pkg/pubkey"
	"github.com/spiretechnology/go-webauthn/pkg/spec"
)

// AuthenticationResponse is the response sent back by the client after an authentication ceremony.
type AuthenticationResponse struct {
	Challenge    string                         `json:"challenge"`
	CredentialID string                         `json:"credentialId"`
	Response     AuthenticatorAssertionResponse `json:"response"`
}

// AuthenticationResult contains the results of verifying the authentication response.
type AuthenticationResult struct {
	Credential Credential
}

func (w *webauthn) VerifyAuthentication(ctx context.Context, user User, res *AuthenticationResponse) (*AuthenticationResult, error) {
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

	// Decode the received credential ID
	credentialID, err := w.options.Codec.DecodeString(res.CredentialID)
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding credential ID")
	}

	// Get the credential with the user and ID
	credential, err := w.options.Credentials.GetCredential(ctx, user, credentialID)
	if err != nil {
		return nil, errutil.Wrapf(err, "getting credential")
	}
	if credential == nil {
		return nil, errutil.Wrap(errs.ErrCredentialNotFound)
	}

	// Decode the public key from the credential store
	publicKey, err := pubkey.Decode(credential.PublicKey)
	if err != nil {
		return nil, errutil.Wrapf(err, "parsing public key")
	}

	// Decode the assertion response response to spec types
	assertionResponse, err := res.Response.Decode(w.options.Codec)
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding attestation response")
	}

	//================================================================================
	// Validate the client data
	//================================================================================

	// Decode the clientDataJSON
	clientData, err := assertionResponse.ClientData()
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding client data")
	}

	// Verify that the decoded clientDataJSON.type is "webauthn.get"
	if clientData.Type != spec.ClientDataTypeGet {
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
	// Verify the returned signature
	//================================================================================

	// Get the public key alg type from the credential
	publicKeyAlg := pubkey.KeyType(credential.PublicKeyAlg)

	// Verify the signature using the signature algorithm for the stored credential
	verified, err := assertionResponse.VerifySignature(publicKey, publicKeyAlg.Hash())
	if err != nil {
		return nil, errutil.Wrapf(err, "verifying signature")
	}
	if !verified {
		return nil, errutil.Wrap(errs.ErrSignatureMismatch)
	}

	return &AuthenticationResult{
		Credential: *credential,
	}, nil
}
