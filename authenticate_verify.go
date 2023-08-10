package webauthn

import (
	"context"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/spec"
)

type AuthenticationResponse struct {
	CredentialID string                         `json:"credentialId"`
	Response     AuthenticatorAssertionResponse `json:"response"`
}

type AuthenticationResult struct{}

func (w *webauthn) VerifyAuthentication(ctx context.Context, userID string, res *AuthenticationResponse) (*AuthenticationResult, error) {
	// Decode the received credential ID
	credentialID, err := w.options.Codec.DecodeString(res.CredentialID)
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding credential ID")
	}

	// Get the credential with the user and ID
	credential, err := w.options.Credentials.GetCredential(ctx, userID, credentialID)
	if err != nil {
		return nil, errutil.Wrapf(err, "getting credential")
	}
	if credential == nil {
		return nil, errutil.Wrap(ErrCredentialNotFound)
	}

	// Decode the public key from the credential store
	publicKey, err := ParsePublicKey(credential.PublicKey)
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
	clientData, err := assertionResponse.DecodeClientData()
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding client data")
	}

	// Verify that the decoded clientDataJSON.type is "webauthn.get"
	if clientData.Type != spec.ClientDataTypeGet {
		return nil, errutil.Wrapf(err, "invalid client data type %q", clientData.Type)
	}

	// Verify that this challenge was issued to the client
	challengeBytes, err := clientData.DecodeChallenge()
	if err != nil {
		return nil, errutil.Wrapf(err, "decoding challenge")
	}
	ok, err := w.options.Challenges.HasChallenge(ctx, userID, challengeBytes)
	if err != nil {
		return nil, errutil.Wrapf(err, "checking challenge")
	}
	if !ok {
		return nil, errutil.Wrap(ErrUnrecognizedChallenge)
	}

	// Remove the challenge from the store. It's no longer needed.
	if err := w.options.Challenges.RemoveChallenge(ctx, userID, challengeBytes); err != nil {
		return nil, errutil.Wrapf(err, "removing challenge")
	}

	//================================================================================
	// Verify the returned signature
	//================================================================================

	// Get the public key alg type from the credential
	publicKeyAlg := PublicKeyType(credential.PublicKeyAlg)

	// Verify the signature using the signature algorithm for the stored credential
	verified, err := assertionResponse.VerifySignature(publicKey, publicKeyAlg.Hash())
	if err != nil {
		return nil, errutil.Wrapf(err, "verifying signature")
	}
	if !verified {
		return nil, errutil.Wrap(ErrSignatureMismatch)
	}

	return &AuthenticationResult{}, nil
}
