package webauthn

import "context"

// Credentials defines the interface for storing registered credentials.
type Credentials interface {
	GetCredentials(ctx context.Context, user User) ([]Credential, error)
	GetCredential(ctx context.Context, user User, credentialID []byte) (*Credential, error)
	StoreCredential(ctx context.Context, user User, credential Credential) error
}
