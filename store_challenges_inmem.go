package webauthn

import "context"

type storedChallege struct {
	userID    string
	challenge [32]byte
}

func challengeKey(user User, challenge [32]byte) storedChallege {
	return storedChallege{
		userID:    user.ID,
		challenge: challenge,
	}
}

func NewChallengesInMemory() Challenges {
	return &inMemChallenges{
		challenges: make(map[storedChallege]struct{}),
	}
}

type inMemChallenges struct {
	challenges map[storedChallege]struct{}
}

func (c *inMemChallenges) StoreChallenge(ctx context.Context, user User, challenge [32]byte) error {
	c.challenges[challengeKey(user, challenge)] = struct{}{}
	return nil
}

func (c *inMemChallenges) HasChallenge(ctx context.Context, user User, challenge [32]byte) (bool, error) {
	_, ok := c.challenges[challengeKey(user, challenge)]
	return ok, nil
}

func (c *inMemChallenges) RemoveChallenge(ctx context.Context, user User, challenge [32]byte) error {
	delete(c.challenges, challengeKey(user, challenge))
	return nil
}