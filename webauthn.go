package webauthn

import (
	"context"
	"encoding/base64"

	"github.com/spiretechnology/go-webauthn/internal/spec"
)

type WebAuthn interface {
	CreateRegistration(ctx context.Context, user User) (*RegistrationChallenge, error)
	VerifyRegistration(ctx context.Context, user User, res *RegistrationResponse) (*RegistrationResult, error)
	CreateAuthentication(ctx context.Context, user User) (*AuthenticationChallenge, error)
	VerifyAuthentication(ctx context.Context, user User, res *AuthenticationResponse) (*AuthenticationResult, error)
}

type Options struct {
	RP             RelyingParty
	Codec          Codec
	PublicKeyTypes []PublicKeyType
	Credentials    Credentials
	Challenges     Challenges
	ChallengeFunc  func() (Challenge, error)
}

func New(options Options) WebAuthn {
	if options.Codec == nil {
		options.Codec = base64.RawURLEncoding
	}
	if options.Challenges == nil {
		options.Challenges = NewChallengesInMemory()
	}
	if options.PublicKeyTypes == nil {
		options.PublicKeyTypes = []PublicKeyType{
			ES256, ES384, ES512,
			PS256, PS384, PS512,
		}
	}
	if options.ChallengeFunc == nil {
		options.ChallengeFunc = spec.GenerateChallenge
	}
	return &webauthn{options}
}

type webauthn struct {
	options Options
}

func (w *webauthn) getPubKeyCredParams() []spec.PubKeyCredParam {
	params := make([]spec.PubKeyCredParam, len(w.options.PublicKeyTypes))
	for i, keyType := range w.options.PublicKeyTypes {
		params[i] = keyType.pubKeyCredParam()
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
