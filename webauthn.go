package webauthn

import (
	"context"
	"encoding/base64"

	"github.com/spiretechnology/go-webauthn/internal/challenge"
	"github.com/spiretechnology/go-webauthn/spec"
	"github.com/spiretechnology/go-webauthn/store"
)

type WebAuthn interface {
	CreateRegistration(ctx context.Context, userID string) (*RegistrationChallenge, error)
	VerifyRegistration(ctx context.Context, userID string, res *RegistrationResponse) (*RegistrationResult, error)
	CreateAuthentication(ctx context.Context, userID string) (*AuthenticationChallenge, error)
	VerifyAuthentication(ctx context.Context, userID string, res *AuthenticationResponse) (*AuthenticationResult, error)
}

type Options struct {
	RP             spec.RelyingParty
	Codec          Codec
	PublicKeyTypes []PublicKeyType
	Users          store.Users
	Credentials    store.Credentials
	Challenges     store.Challenges
	ChallengeFunc  func() ([32]byte, error)
}

func New(options Options) WebAuthn {
	if options.Codec == nil {
		options.Codec = base64.RawURLEncoding
	}
	if options.Challenges == nil {
		options.Challenges = store.NewChallengesInMemory()
	}
	if options.PublicKeyTypes == nil {
		options.PublicKeyTypes = []PublicKeyType{
			ES256, ES384, ES512,
			PS256, PS384, PS512,
		}
	}
	if options.ChallengeFunc == nil {
		options.ChallengeFunc = challenge.GenerateChallenge
	}
	return &webauthn{options}
}

type webauthn struct {
	options Options
}

func (w *webauthn) getPubKeyCredParams() []spec.PubKeyCredParam {
	params := make([]spec.PubKeyCredParam, len(w.options.PublicKeyTypes))
	for i, keyType := range w.options.PublicKeyTypes {
		params[i] = keyType.PubKeyCredParam()
	}
	return params
}

func (w *webauthn) supportsPublicKeyAlg(alg PublicKeyType) bool {
	for _, keyType := range w.options.PublicKeyTypes {
		if keyType == alg {
			return true
		}
	}
	return false
}
