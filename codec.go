package webauthn

// Codec defines an interface for encoding and decoding binary data to and from a string.
type Codec interface {
	EncodeToString([]byte) string
	DecodeString(string) ([]byte, error)
}
