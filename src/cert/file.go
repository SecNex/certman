package cert

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/secnex/certman/provider/store"
)

func (c *Certificate) Output(cert *[]byte) ([]byte, []byte, error) {
	var certPEM, keyPEM []byte
	if cert == nil {
		cert, err := c.Sign()
		if err != nil {
			return nil, nil, err
		}
		certPEM = pemEncodeCertificate(cert)
	} else {
		certPEM = pemEncodeCertificate(*cert)
	}

	key, err := c.EncodePrivateKey()
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pemEncodePrivateKey(key)

	return certPEM, keyPEM, nil
}

func (c *Certificate) EncodePrivateKey() ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(c.PrivateKey)
}

func pemEncodePrivateKey(key []byte) []byte {
	return pemEncode("RSA PRIVATE KEY", key)
}

func pemEncodeCertificate(cert []byte) []byte {
	return pemEncode("CERTIFICATE", cert)
}

func pemEncode(keyType string, key []byte) []byte {
	block := &pem.Block{
		Type:  keyType,
		Bytes: key,
	}
	return pem.EncodeToMemory(block)
}

func generateSubjectKeyIdentifier(pubKey *rsa.PublicKey) ([]byte, error) {
	if pubKey == nil {
		return nil, fmt.Errorf("public key is required")
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		log.Println("Error to marshal public key:", err)
		return nil, err
	}
	hash := sha1.Sum(pubKeyBytes)
	return hash[:], nil
}

func generateAuthorityKeyIdentifier(pubKey *rsa.PublicKey) ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	hash := sha1.Sum(pubKeyBytes)
	return hash[:], nil
}

func SaveCertificate(cert *[]byte, key *[]byte, fileCert string, fileKey string, storage store.Storage) error {
	if err := saveFile(cert, fileCert); err != nil {
		return err
	}
	if err := saveFile(key, fileKey); err != nil {
		return err
	}
	return nil
}

func saveFile(data *[]byte, path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("file %s already exists", path)
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}

	_, err = file.Write(*data)
	if err != nil {
		return err
	}

	err = file.Close()
	return err
}

func loadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := loadFile(path)
	if err != nil {
		return nil, err
	}

	log.Printf("Loaded file content: %s", string(data))

	block, _ := pem.Decode(data)
	if block == nil {
		log.Println("Error to decode PEM block")
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Println("Error to parse private key:", err)
		return nil, err
	}

	return key.(*rsa.PrivateKey), nil
}

func LoadCertificate(path string) (*x509.Certificate, error) {
	data, err := loadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func DecodeCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func DecodePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key.(*rsa.PrivateKey), nil
}
