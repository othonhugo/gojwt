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

	// ErrTokenExpired is returned when the token has expired
	ErrTokenExpired = errors.New("jwt: token is expired")

	// ErrTokenNotValidYet is returned when the token is used before its 'nbf' (not before) time
	ErrTokenNotValidYet = errors.New("jwt: token is not valid yet")

	// ErrTokenUsedBeforeIssued is returned when the token is used before its 'iat' (issued at) time
	ErrTokenUsedBeforeIssued = errors.New("jwt: token used before issued")
)

// unsupportedAlgorithmError indicates the algorithm is not supported
type unsupportedAlgorithmError struct {
	alg string
}

func (e unsupportedAlgorithmError) Error() string {
	return fmt.Sprintf("jwt: unsupported algorithm: %s", e.alg)
}

// unsupportedTypeError indicates the token type is not supported
type unsupportedTypeError struct {
	typ string
}

func (e unsupportedTypeError) Error() string {
	return fmt.Sprintf("jwt: unsupported type: %s", e.typ)
}
