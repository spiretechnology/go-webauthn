package challenge

import (
	"crypto/rand"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
)

// GenerateChallenge generates a random challenge for WebAuthn authentication. The challenge should be sent to the
// client, then signed by the client device and sent back to the server.
func GenerateChallenge() ([32]byte, error) {
	var challenge [32]byte
	_, err := rand.Read(challenge[:])
	if err != nil {
		return challenge, errutil.Wrapf(err, "reading random bytes")
	}
	return challenge, nil
}
