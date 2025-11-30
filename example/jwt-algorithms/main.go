// Quickstart example for gojwt
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/othonhugo/gojwt"
)

var (
	secret = []byte("your-secret-key")

	claims = gojwt.Claims{
		Issuer:    "my-app",
		Subject:   "user-123",
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
	}
)

func main() {
	// HS256 (HMAC-SHA256) - 32 byte signature
	header256 := gojwt.Header{Alg: gojwt.HS256}

	encodeAndPrint(header256)

	// HS384 (HMAC-SHA384) - 48 byte signature
	header384 := gojwt.Header{Alg: gojwt.HS384}

	encodeAndPrint(header384)

	// HS512 (HMAC-SHA512) - 64 byte signature
	header512 := gojwt.Header{Alg: gojwt.HS512}

	encodeAndPrint(header512)
}

func encodeAndPrint(header gojwt.Header) {
	var decoded gojwt.Claims

	token, err := gojwt.Marshal(header, claims, secret)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Token (%s): %s\n", header.Alg, token)

	// Verify and decode the token
	err = gojwt.Unmarshal(token, &decoded, secret)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Subject (%s): %s\n\n", header.Alg, decoded.Subject)
}
