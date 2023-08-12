package webauthn

import (
	"context"
	"crypto/rand"
	"encoding/base64"

	"github.com/spiretechnology/go-jwt/v2"
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
	Tokener        Tokener
	ChallengeFunc  func() (challenge.Challenge, error)
}

func New(options Options) WebAuthn {
	if options.Codec == nil {
		options.Codec = base64.RawURLEncoding
	}
	if options.PublicKeyTypes == nil {
		options.PublicKeyTypes = pubkey.AllKeyTypes
	}
	if options.ChallengeFunc == nil {
		options.ChallengeFunc = challenge.GenerateChallenge
	}
	if options.Tokener == nil {
		secret := make([]byte, 64)
		rand.Read(secret)
		options.Tokener = NewJwtTokener(
			jwt.HS256Signer(secret),
			jwt.HS256Verifier(secret),
		)
	}
	return &webauthn{options}
}

type webauthn struct {
	options Options
}
