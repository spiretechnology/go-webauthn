package webauthn

// RelyingParty is the ID and name or the relying party.
type RelyingParty struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
