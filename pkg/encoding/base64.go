package encoding

import (
	"encoding/base64"
	"strings"
)

func EncodeJWTBase64(plaintext []byte) string {
	return DeleteBase64Padding(base64.URLEncoding.EncodeToString(plaintext))
}

func DecodeJWTBase64(encoded string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(AppendBase64Padding(encoded))
}

func AppendBase64Padding(v string) string {
	switch len(v) % 4 {
	case 2:
		return v + "=="
	case 3:
		return v + "="
	}

	return v
}

func DeleteBase64Padding(v string) string {
	return strings.TrimRight(v, "=")
}
