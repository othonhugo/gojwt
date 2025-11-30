// Example of custom claims
// nolint:all // Example code: focus on clarity over style
package main

import (
	"fmt"
	"time"

	"github.com/othonhugo/gojwt"
)

type CustomClaims struct {
	gojwt.Claims
	UserID   int    `json:"user_id"`
	Role     string `json:"role"`
	IsActive bool   `json:"is_active"`
}

func main() {
	secret := []byte("secret-key")

	// Create token
	header := gojwt.Header{Alg: gojwt.HS256}

	// Create token with custom claims
	customClaims := CustomClaims{
		Claims: gojwt.Claims{
			Subject:   "john.doe",
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		},
		UserID:   12345,
		Role:     "admin",
		IsActive: true,
	}

	token, _ := gojwt.Marshal(header, customClaims, secret)

	// Decode custom claims
	var decoded CustomClaims
	gojwt.Unmarshal(token, &decoded, secret)

	fmt.Printf("User ID: %d, Role: %s\n", decoded.UserID, decoded.Role)
}
