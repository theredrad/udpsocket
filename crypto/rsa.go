// An implementation of RSA as asymmetric cryptographer

package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
)

// An implementation of RSA for asymmetric cryptography
type RSACrypto struct {
	keySize    int
	privateKey *rsa.PrivateKey
}

// Returns a new instance of RSA implementation by generating a new key
func NewRSA(keySize int) (*RSACrypto, error) {
	key, err := GenerateRSAKey(keySize)
	if err != nil {
		return nil, err
	}
	return &RSACrypto{
		keySize:    keySize,
		privateKey: key,
	}, nil
}

// Returns a new instance of RSA implementation by the given private key
func NewRSAFromPK(key *rsa.PrivateKey) *RSACrypto {
	return &RSACrypto{
		keySize:    key.Size(),
		privateKey: key,
	}
}

// Returns a new instance of RSA implementation by the given private key bytes
func NewRSAFromBytes(pk []byte) (*RSACrypto, error) {
	p, _ := pem.Decode(pk)

	key, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		return nil, err
	}

	return &RSACrypto{
		keySize:    key.Size(),
		privateKey: key,
	}, nil
}

// Decrypts cipher
func (c *RSACrypto) Decrypt(cipher []byte) ([]byte, error) {
	return c.privateKey.Decrypt(nil, cipher, &rsa.OAEPOptions{Hash: crypto.SHA1})
}

// Returns public key bytes
func (c *RSACrypto) GetPublicKey() []byte {
	return c.privateKey.PublicKey.N.Bytes()
}

type RSAEncryptor struct {
	pk *rsa.PublicKey
}

func NewRSAEncryptorFromPK(key *rsa.PublicKey) *RSAEncryptor {
	return &RSAEncryptor{
		pk: key,
	}
}

func (c *RSAEncryptor) Encrypt(payload []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, c.pk, payload, nil)
}

// Generates a new RSA key by the given size
func GenerateRSAKey(size int) (*rsa.PrivateKey, error) {
	reader := rand.Reader
	return rsa.GenerateKey(reader, size)
}
