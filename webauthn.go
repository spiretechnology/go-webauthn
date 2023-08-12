package webauthn

import (
	"context"
	"encoding/base64"

	"github.com/spiretechnology/go-webauthn/internal/spec"
	"github.com/spiretechnology/go-webauthn/pkg/challenge"
	"github.com/spiretechnology/go-webauthn/pkg/codec"
	"github.com/spiretechnology/go-webauthn/pkg/pubkey"
)

type WebAuthn interface {
	CreateRegistration(ctx context.Context, user User) (*RegistrationChallenge, error)
	VerifyRegistration(ctx context.Context, user User, res *RegistrationResponse) (*RegistrationResult, error)
	CreateAuthentication(ctx context.Context, user User) (*AuthenticationChallenge, error)
	VerifyAuthentication(ctx context.Context, user User, res *AuthenticationResponse) (*AuthenticationResult, error)
}

type Options struct {
	RP             RelyingParty
	Codec          codec.Codec
	PublicKeyTypes []pubkey.KeyType
	Credentials    Credentials
	Challenges     Challenges
	ChallengeFunc  func() (challenge.Challenge, error)
}

func New(options Options) WebAuthn {
	if options.Codec == nil {
		options.Codec = base64.RawURLEncoding
	}
	if options.Challenges == nil {
		options.Challenges = NewChallengesInMemory()
	}
	if options.PublicKeyTypes == nil {
		options.PublicKeyTypes = []pubkey.KeyType{
			pubkey.ES256, pubkey.ES384, pubkey.ES512,
			pubkey.PS256, pubkey.PS384, pubkey.PS512,
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
		params[i] = spec.PubKeyCredParam{
			Type: "public-key",
			Alg:  int(keyType),
		}
	}
	return params
}

func (w *webauthn) supportsPublicKeyAlg(alg pubkey.KeyType) bool {
	for _, keyType := range w.options.PublicKeyTypes {
		if keyType == alg {
			return true
		}
	}
	return false
}
