package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"hash"
	"strings"
	"time"
)

// Constants for JWT algorithms and types
const (
	HS256 = "HS256"
	HS384 = "HS384"
	HS512 = "HS512"
	JWT   = "JWT"
)

// Header represents the JWT header
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Claims implements the Claimer interface and includes standard JWT claims.
type Claims struct {
	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ID        string `json:"jti,omitempty"`
}

// Valid validates the claims against the standard JWT rules.
func (c Claims) Valid() error {
	now := time.Now().Unix()

	if c.ExpiresAt > 0 && now >= c.ExpiresAt {
		return ErrTokenExpired
	}

	if c.NotBefore > 0 && now < c.NotBefore {
		return ErrTokenNotValidYet
	}

	if c.IssuedAt > 0 && now < c.IssuedAt {
		return ErrTokenUsedBeforeIssued
	}

	return nil
}

func (h *Header) marshal() (string, error) {
	var jsonBuf bytes.Buffer

	jsonEnc := json.NewEncoder(&jsonBuf)
	jsonEnc.SetEscapeHTML(false)

	if err := jsonEnc.Encode(h); err != nil {
		return "", err
	}

	jsonHeader := bytes.TrimSpace(jsonBuf.Bytes())

	return encodeJWTBase64(jsonHeader), nil
}

func (h *Header) unmarshal(encodedHeader string) error {
	jsonHeader, err := decodeJWTBase64(encodedHeader)

	if err != nil {
		return err
	}

	return json.Unmarshal(jsonHeader, h)
}

func (h *Header) signer(secret []byte) (hash.Hash, error) {
	switch strings.ToUpper(h.Alg) {
	case HS256:
		return hmac.New(sha256.New, secret), nil
	case HS384:
		return hmac.New(sha512.New384, secret), nil
	case HS512:
		return hmac.New(sha512.New, secret), nil
	}

	return nil, unsupportedAlgorithmError{alg: h.Alg}
}

// payload represents the JWT payload (claims)
type payload struct {
	claims any
}

func (p *payload) marshal() (string, error) {
	var buf bytes.Buffer

	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)

	if err := enc.Encode(p.claims); err != nil {
		return "", err
	}

	jsonClaims := bytes.TrimSpace(buf.Bytes())

	return encodeJWTBase64(jsonClaims), nil
}

func (p *payload) unmarshal(encodedPayload string) error {
	jsonClaims, err := decodeJWTBase64(encodedPayload)

	if err != nil {
		return err
	}

	return json.Unmarshal(jsonClaims, p.claims)
}

// token represents the full JWT
type token struct {
	header  Header
	payload payload
}

func (t *token) marshal(secret []byte) (string, error) {
	signer, err := t.header.signer(secret)

	if err != nil {
		return "", err
	}

	tokenHeader, err := t.header.marshal()

	if err != nil {
		return "", err
	}

	tokenPayload, err := t.payload.marshal()

	if err != nil {
		return "", err
	}

	signingMessage := tokenHeader + "." + tokenPayload

	if _, err := signer.Write([]byte(signingMessage)); err != nil {
		return "", err
	}

	tokenSignature := encodeJWTBase64(signer.Sum(nil))

	b64vals := b64values{
		header:    tokenHeader,
		payload:   tokenPayload,
		signature: tokenSignature,
	}

	return b64vals.marshal(), nil
}

func (t *token) unmarshal(jws string, secret []byte) error {
	b64vals := b64values{}

	if err := b64vals.unmarshal(jws); err != nil {
		return err
	}

	expectedSignature, err := decodeJWTBase64(b64vals.signature)
	if err != nil {
		return ErrInvalidToken
	}

	if err := t.header.unmarshal(b64vals.header); err != nil {
		return err
	}

	signer, err := t.header.signer(secret)

	if err != nil {
		return err
	}

	signingMessage := b64vals.header + "." + b64vals.payload

	if _, err := signer.Write([]byte(signingMessage)); err != nil {
		return err
	}

	computedSignature := signer.Sum(nil)

	if !hmac.Equal(computedSignature, expectedSignature) {
		return ErrSignatureMismatch
	}

	return t.payload.unmarshal(b64vals.payload)
}
