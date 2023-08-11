package webauthn

// AuthType defines a set of methods of authentication (eg. hardware key, biometric, etc).
type AuthType uint8

const (
	// HardwareKey is a hardware authenticator.
	HardwareKey = AuthType(1 << iota)
	// Biometric is a fingerprint or face scan.
	Biometric
	// AllAuthTypes is a bitmask of all auth types.
	AllAuthTypes = AuthType(0xFF)
)
