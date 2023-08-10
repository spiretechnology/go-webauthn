package store

import "context"

type storedChallege struct {
	userID    string
	challenge [32]byte
}

func NewChallengesInMemory() Challenges {
	return &inMemChallenges{
		challenges: make(map[storedChallege]struct{}),
	}
}

type inMemChallenges struct {
	challenges map[storedChallege]struct{}
}

func (c *inMemChallenges) StoreChallenge(ctx context.Context, userID string, challenge [32]byte) error {
	c.challenges[storedChallege{userID: userID, challenge: challenge}] = struct{}{}
	return nil
}

func (c *inMemChallenges) HasChallenge(ctx context.Context, userID string, challenge [32]byte) (bool, error) {
	_, ok := c.challenges[storedChallege{userID: userID, challenge: challenge}]
	return ok, nil
}

func (c *inMemChallenges) RemoveChallenge(ctx context.Context, userID string, challenge [32]byte) error {
	delete(c.challenges, storedChallege{userID: userID, challenge: challenge})
	return nil
}
