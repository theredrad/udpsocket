package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// Calculates the HMAC of params by the given key
func HMAC(key []byte, params ...[]byte) []byte {
	hash := hmac.New(sha256.New, key)
	for _, param := range params {
		hash.Write(param)
	}
	return hash.Sum(nil)
}

// Compares two hmac parameters
func HMACEqual(mac1, mac2 []byte) bool {
	return hmac.Equal(mac1, mac2)
}
