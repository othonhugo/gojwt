package jwt

import (
	"encoding/base64"
	"strings"
)

// b64values holds the base64 encoded parts of the JWT
type b64values struct {
	header, payload, signature string
}

// marshal returns the JWT as a string.
func (v *b64values) marshal() string {
	return strings.Join([]string{v.header, v.payload, v.signature}, ".")
}

// unmarshal populates the b64values from a JWT string.
func (v *b64values) unmarshal(s string) error {
	fields := strings.SplitN(s, ".", 3)
	if len(fields) != 3 {
		return ErrInvalidToken
	}

	*v = b64values{
		header:    fields[0],
		payload:   fields[1],
		signature: fields[2],
	}
	return nil
}

// encodeJWTBase64 encodes a byte slice to a base64 string.
func encodeJWTBase64(plaintext []byte) string {
	return base64.RawURLEncoding.EncodeToString(plaintext)
}

// decodeJWTBase64 decodes a base64 string to a byte slice.
func decodeJWTBase64(encoded string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(encoded)
}
