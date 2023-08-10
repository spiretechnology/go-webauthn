package store

import "context"

type Credential struct {
	ID           []byte
	Type         string
	PublicKey    []byte
	PublicKeyAlg int
}

type Credentials interface {
	GetCredentials(ctx context.Context, userID string) ([]Credential, error)
	GetCredential(ctx context.Context, userID string, credentialID []byte) (*Credential, error)
	StoreCredential(ctx context.Context, userID string, credential Credential) error
}
