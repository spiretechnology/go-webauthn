package webauthn

import "github.com/spiretechnology/go-webauthn/pkg/authenticators"

// Credential represents a registered credential.
type Credential struct {
	// ID is the `rawId` of the credential, as defined in the WebAuthn spec.
	ID []byte
	// Type is the `type` of the credential, as defined in the WebAuthn spec. Always "public-key".
	Type string
	// PublicKey is the `publicKey` of the credential, as defined in the WebAuthn spec.
	PublicKey []byte
	// PublicKeyAlg is the `publicKeyAlg` of the credential, as defined in the WebAuthn spec.
	// See `PublicKeyType` for supported values.
	PublicKeyAlg int
}

// CredentialMeta contains metadata about a credential. Storing this information is not needed for
// the authentication flow, but may be useful for other purposes.
type CredentialMeta struct {
	// Authenticator is the model of the authenticator used to create this credential. May be nil.
	Authenticator *authenticators.Authenticator
}
