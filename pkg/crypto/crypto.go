package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
)

var (
	NewSHA256 = sha256.New
	NewSHA384 = sha512.New384
	NewSHA512 = sha512.New
	NewHMAC   = hmac.New
	Equal     = hmac.Equal
)
