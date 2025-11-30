package jwt

import (
	"encoding/base64"
	"strings"
)

type b64values struct {
	header, payload, signature string
}

func (v *b64values) marshal() string {
	return strings.Join([]string{v.header, v.payload, v.signature}, ".")
}

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

func encodeJWTBase64(plaintext []byte) string {
	return base64.RawURLEncoding.EncodeToString(plaintext)
}

func decodeJWTBase64(encoded string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(encoded)
}
