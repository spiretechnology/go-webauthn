package authenticators

import (
	_ "embed"
)

// AAGUID is a unique identifier for an authenticator model.
type AAGUID [16]byte

// Authenticator contains information about a known authenticator model.
type Authenticator struct {
	AAGUID       AAGUID
	Manufacturer string
	Model        string
	Name         string
}

// LookupAuthenticator returns information about a known authenticator model.
func LookupAuthenticator(aaguid AAGUID) *Authenticator {
	device, ok := knownAuthenticators[aaguid]
	if !ok {
		return nil
	}
	return &device
}
