package webauthn

import "context"

type Credential struct {
	ID           []byte
	Type         string
	PublicKey    []byte
	PublicKeyAlg int
}

type Credentials interface {
	GetCredentials(ctx context.Context, user User) ([]Credential, error)
	GetCredential(ctx context.Context, user User, credentialID []byte) (*Credential, error)
	StoreCredential(ctx context.Context, user User, credential Credential) error
}
