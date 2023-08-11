package webauthn

// User contains the details of a user to be registered or authenticated.
// Conforms to the WebAuthn spec.
type User struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}
