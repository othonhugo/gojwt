// Example of token creation and validation.
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/othonhugo/gojwt"
)

func main() {
	secret := []byte("secret-key")

	// Create token
	header := gojwt.Header{Alg: gojwt.HS256}
	claims := gojwt.Claims{
		Subject:   "user-456",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	token, _ := gojwt.Marshal(header, claims, secret)

	// Validate token
	var decoded gojwt.Claims
	err := gojwt.Unmarshal(token, &decoded, secret)
	if err != nil {
		// Token is invalid, expired, or signature doesn't match
		log.Println("Validation failed:", err)
	} else {
		fmt.Println("Token is validated:", token)
	}
}
