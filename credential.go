package webauthn

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