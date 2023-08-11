package testutil

import "encoding/base64"

// Encode encodes binary data into a base64url string. This works the same way as the default Codec.
func Encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// Decodes a base64url string into binary data. This works the same way as the default Codec, except that
// it panics on error.
func Decode(str string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return b
}
