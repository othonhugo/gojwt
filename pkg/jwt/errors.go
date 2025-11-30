package jwt

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidToken is returned when the token is invalid
	ErrInvalidToken = errors.New("jwt: invalid token")

	// ErrSignatureMismatch is returned when the signature does not match
	ErrSignatureMismatch = errors.New("jwt: signature mismatch during verification")
)

// UnsupportedAlgorithmError indicates the algorithm is not supported
type UnsupportedAlgorithmError struct {
	alg string
}

func (e UnsupportedAlgorithmError) Error() string {
	return fmt.Sprintf("jwt: unsupported algorithm: %s", e.alg)
}

// UnsupportedTypeError indicates the token type is not supported
type UnsupportedTypeError struct {
	typ string
}

func (e UnsupportedTypeError) Error() string {
	return fmt.Sprintf("jwt: unsupported type: %s", e.typ)
}
