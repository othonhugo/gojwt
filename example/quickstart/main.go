// Quickstart example for gojwt
// nolint:all // Example code: focus on clarity over style
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/othonhugo/gojwt"
)

func main() {
	secret := []byte("your-secret-key")

	// Create a token
	header := gojwt.Header{
		Alg: gojwt.HS256,
		Typ: gojwt.JWT,
	}

	claims := gojwt.Claims{
		Issuer:    "my-app",
		Subject:   "user-123",
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	token, err := gojwt.Marshal(header, claims, secret)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Token:", token)

	// Verify and decode the token
	var decoded gojwt.Claims
	err = gojwt.Unmarshal(token, &decoded, secret)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Subject: %s\n", decoded.Subject)
}
