package cert

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const saltSize = 16
const keySize = 32

func Encrypt(privKey *rsa.PrivateKey, passphrase string) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := pbkdf2.Key([]byte(passphrase), salt, 10000, keySize, sha256.New)
	privKeyDER := x509.MarshalPKCS1PrivateKey(privKey)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	encrypted := gcm.Seal(nonce, nonce, privKeyDER, nil)
	return append(salt, encrypted...), nil
}

func Decrypt(encryptedKey []byte, passphrase string) (*rsa.PrivateKey, error) {
	salt := encryptedKey[:saltSize]
	encrypted := encryptedKey[saltSize:]

	key := pbkdf2.Key([]byte(passphrase), salt, 10000, keySize, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, encrypted := encrypted[:nonceSize], encrypted[nonceSize:]

	privKeyDER, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return x509.ParsePKCS1PrivateKey(privKeyDER)
}
