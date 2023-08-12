package main

import (
	"bytes"
	"context"

	"github.com/spiretechnology/go-webauthn"
)

type Credentials struct {
	credentialsByUser map[string][]webauthn.Credential
}

func (c *Credentials) GetCredentials(ctx context.Context, user webauthn.User) ([]webauthn.Credential, error) {
	if c.credentialsByUser == nil {
		return nil, nil
	}
	return c.credentialsByUser[user.ID], nil
}

func (c *Credentials) GetCredential(ctx context.Context, user webauthn.User, credentialID []byte) (*webauthn.Credential, error) {
	if c.credentialsByUser == nil {
		return nil, nil
	}
	for _, credential := range c.credentialsByUser[user.ID] {
		if bytes.Equal(credential.ID, credentialID) {
			return &credential, nil
		}
	}
	return nil, nil
}

func (c *Credentials) StoreCredential(ctx context.Context, user webauthn.User, credential webauthn.Credential, meta webauthn.CredentialMeta) error {
	if c.credentialsByUser == nil {
		c.credentialsByUser = make(map[string][]webauthn.Credential)
	}
	c.credentialsByUser[user.ID] = append(c.credentialsByUser[user.ID], credential)
	return nil
}
