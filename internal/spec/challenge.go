package spec

import (
	"crypto/rand"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
)

// ChallengeSize is the size of a challenge in bytes.
const ChallengeSize = 32

// Challenge is a randomly generated value that is sent to the client and signed by the client device.
type Challenge = [ChallengeSize]byte

// GenerateChallenge generates a random challenge for WebAuthn authentication. The challenge should be sent to the
// client, then signed by the client device and sent back to the server.
func GenerateChallenge() (Challenge, error) {
	var challenge Challenge
	_, err := rand.Read(challenge[:])
	if err != nil {
		return challenge, errutil.Wrapf(err, "reading random bytes")
	}
	return challenge, nil
}
