package jwt

import (
	"github.com/othonhugo/go-jwt/pkg/jwt"
)

const (
	HS256 = jwt.HS256
	HS384 = jwt.HS384
	HS512 = jwt.HS512
)

var (
	ErrInvalidToken      = jwt.ErrInvalidToken
	ErrSignatureMismatch = jwt.ErrSignatureMismatch
)

type Header = jwt.Header
type Claims = jwt.Claims

func Marshal(header Header, claims any, secret []byte) (string, error) {
	return jwt.Marshal(header, claims, secret)
}

func Unmarshal(jws string, claims any, secret []byte) error {
	return jwt.Unmarshal(jws, claims, secret)
}
