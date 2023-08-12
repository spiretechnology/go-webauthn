package webauthn

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/spiretechnology/go-jwt/v2"
	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/pkg/challenge"
)

// NewJwtTokener creates a new tokener that issues JWT tokens.
func NewJwtTokener(signer jwt.Signer, verifier jwt.Verifier) Tokener {
	return &jwtTokener{signer, verifier}
}

type jwtTokener struct {
	signer   jwt.Signer
	verifier jwt.Verifier
}

type jwtTokenClaims struct {
	UserID        string `json:"uid"`
	ChallengeHash string `json:"chash"`
	ExpiresAt     int64  `json:"exp"`
}

func (t *jwtTokener) CreateToken(challenge challenge.Challenge, user User) (string, error) {
	challengeHash := sha256.Sum256(challenge[:])
	claims := jwtTokenClaims{
		UserID:        user.ID,
		ChallengeHash: hex.EncodeToString(challengeHash[:]),
		ExpiresAt:     time.Now().Add(15 * time.Minute).Unix(),
	}
	return jwt.Create(claims, t.signer)
}

func (t *jwtTokener) VerifyToken(token string, challenges challenge.Challenge, user User) error {
	// Parse the token to a JWT
	jwtToken, err := jwt.Parse(token)
	if err != nil {
		return errutil.Wrapf(err, "parsing jwt token")
	}

	// Verify the token's signature
	valid, err := jwtToken.Verify(t.verifier)
	if err != nil {
		return errutil.Wrapf(err, "verifying jwt token")
	}
	if !valid {
		return errutil.New("invalid jwt token")
	}

	// Unmarshal the claims in the token
	var claims jwtTokenClaims
	if err := jwtToken.Claims(&claims); err != nil {
		return errutil.Wrapf(err, "unmarshaling jwt token claims")
	}

	// Verify the challenge hash in the token matches the challenge hash in the request
	challengeHash := sha256.Sum256(challenges[:])
	if claims.ChallengeHash != hex.EncodeToString(challengeHash[:]) {
		return errutil.New("invalid challenge hash")
	}

	// Verify the expiration time of the token
	if time.Now().Unix() > claims.ExpiresAt {
		return errutil.New("token is expired")
	}

	// Verify the user ID in the token matches the user ID in the request
	if claims.UserID != user.ID {
		return errutil.New("invalid user ID")
	}
	return nil
}
