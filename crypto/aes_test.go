package crypto

import (
	"bytes"
	"testing"
)

var (
	plaintext = []byte("test")
	aesKey    = []byte{113, 110, 25, 53, 11, 53, 68, 33, 17, 36, 22, 7, 125, 11, 35, 16, 83, 61, 59, 49, 31, 22, 69, 17, 24, 125, 11, 35, 16, 83, 61, 59}
)

func TestAES_Encrypt(t *testing.T) {
	aes := NewAES(AES_CBC)
	c, err := aes.Encrypt(plaintext, aesKey)
	if err != nil {
		t.Errorf("expected cipher, got error: %s", err)
		t.FailNow()
	}

	d, err := aes.Decrypt(c, aesKey)
	if err != nil {
		t.Errorf("expected decrypted text, got error: %s", err)
		t.FailNow()
	}

	if bytes.Compare(d, plaintext) != 0 {
		t.Error("expected decrypted text, got wrong value")
		t.FailNow()
	}
}
