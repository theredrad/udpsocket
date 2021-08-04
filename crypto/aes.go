// An implementation of AES as symmetric cryptographer

package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// errors
var (
	ErrInvalidAESMode              = errors.New("invalid AES encryption mode")
	ErrCiphertextTooShortToDecrypt = errors.New("ciphertext is too short to decrypt")
	ErrCiphertextIsEmpty           = errors.New("cipher text is empty")
	ErrCiphertextIsNotBlockAligned = errors.New("ciphertext is not block-aligned")
)

// AES mode type
type AESMode uint

// list of supported AES mode
const (
	AES_CBC AESMode = iota
)

// AES implementation for symmetric cryptography
type AES struct {
	mode AESMode
}

// NewAES returns a new instance of AES implementation
func NewAES(mode AESMode) *AES {
	return &AES{
		mode: mode,
	}
}

// Encrypts a byte array by the given key
func (a *AES) Encrypt(plainBytes, key []byte) ([]byte, error) {
	switch a.mode {
	case AES_CBC:
		return a.cbcEncrypt(plainBytes, key)
	default:
		return nil, ErrInvalidAESMode
	}
}

// Decrypts the ciphertext bytes by the given key
func (a *AES) Decrypt(cipherBytes, key []byte) ([]byte, error) {
	switch a.mode {
	case AES_CBC:
		return a.cbcDecrypt(cipherBytes, key)
	default:
		return nil, ErrInvalidAESMode
	}
}

// Encrypts a byte array with by the given key with CBC mode using PKCS#7 padding
func (a *AES) cbcEncrypt(plainBytes, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	plainBytes = pkcs7Padding(plainBytes, blockSize)
	cipherText := make([]byte, blockSize+len(plainBytes))
	iv := cipherText[:blockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[blockSize:], plainBytes)
	return cipherText, nil
}

// Decrypts a byte array with by the given key with CBC mode using PKCS#7 padding
func (a *AES) cbcDecrypt(ciphertext, key []byte) ([]byte, error) {
	var block cipher.Block

	var err error
	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, ErrCiphertextTooShortToDecrypt
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(ciphertext, ciphertext)
	ciphertext, err = pkcs7UnPadding(ciphertext, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// Adds padding to the ciphertext by PKCS#7
func pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	return append(ciphertext, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

// Removes padding from the ciphertext by PKCS#7
func pkcs7UnPadding(ciphertext []byte, blockSize int) ([]byte, error) {
	length := len(ciphertext)
	if length == 0 {
		return nil, ErrCiphertextIsEmpty
	}
	if length%blockSize != 0 {
		return nil, ErrCiphertextIsNotBlockAligned
	}
	padLen := int(ciphertext[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(ciphertext, ref) {
		return ciphertext, nil
	}
	return ciphertext[:length-padLen], nil
}
