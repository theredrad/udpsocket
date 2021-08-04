package udpsocket

import (
	"crypto/rand"
	"net"
	"udpsocket/crypto"
)

// A struct to manage sessions secrets
type sessionManager struct {
	sHMACKey []byte //session random key
	cHMACKey []byte //cookie random key
}

// Returns a new session manager
// Generates new random secrets for cookies & session IDs
func newSessionManager() (*sessionManager, error) {
	sessionHMAC := make([]byte, 32)
	_, err := rand.Read(sessionHMAC)
	if err != nil {
		return nil, err
	}

	cookieHMAC := make([]byte, 32)
	_, err = rand.Read(cookieHMAC)
	if err != nil {
		return nil, err
	}

	return &sessionManager{
		sHMACKey: sessionHMAC,
		cHMACKey: cookieHMAC,
	}, nil
}

// Generates a cookie for an UDP address with params
func (s *sessionManager) GetAddrCookieHMAC(addr *net.UDPAddr, params ...[]byte) []byte {
	return s.GetCookieHMAC(append([][]byte{addr.IP}, params...)...)
}

// Generates a cookie for a byte array with the cookie secret
func (s *sessionManager) GetCookieHMAC(params ...[]byte) []byte {
	return crypto.HMAC(s.cHMACKey, params...)
}

// Generates a session HMAC with the params
func (s *sessionManager) GetSessionHMAC(params ...[]byte) []byte {
	return crypto.HMAC(s.sHMACKey, params...)
}

// Generate a new random session ID for the address & the user ID
func (s *sessionManager) GenerateSessionID(addr *net.UDPAddr, userID string) ([]byte, error) {
	sessionKey := make([]byte, 32)
	_, err := rand.Read(sessionKey)
	if err != nil {
		return nil, err
	}

	return append(s.GetSessionHMAC(addr.IP, []byte(userID)), sessionKey...), nil
}
