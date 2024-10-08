package cert

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
)

func SaveCertificate(key *[]byte, cert *[]byte, format string, path string, name string) error {
	log.Println("Saving certificate...")
	if _, err := os.Stat(path + fmt.Sprintf("/certs/%s.pem", name)); !os.IsNotExist(err) {
		return errors.New("certificate already exists")
	}
	if _, err := os.Stat(path + fmt.Sprintf("/private/%s.key", name)); !os.IsNotExist(err) {
		return errors.New("key already exists")
	}

	certFile, err := os.Create(path + fmt.Sprintf("/certs/%s.pem", name))
	if err != nil {
		return err
	}
	defer certFile.Close()

	keyFile, err := os.Create(path + fmt.Sprintf("/private/%s.key", name))
	if err != nil {
		return err
	}
	defer keyFile.Close()

	if _, err := certFile.Write(*cert); err != nil {
		return err
	}
	log.Println("Certificate saved to:", path+fmt.Sprintf("/certs/%s.pem", name))

	if _, err := keyFile.Write(*key); err != nil {
		return err
	}
	log.Println("Key saved to:", path+fmt.Sprintf("/private/%s.key", name))

	return nil
}

func CreateFolderStructure(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		os.MkdirAll(path, 0755)
		os.MkdirAll(fmt.Sprintf("%s/certs", path), 0755)
		os.MkdirAll(fmt.Sprintf("%s/private", path), 0755)
	}
	return nil
}

func LoadCertificate(path string, name string, passphrase *string) (*Certificate, error) {
	log.Println("Loading certificate...")
	certPath := path + fmt.Sprintf("/certs/%s.pem", name)
	keyPath := path + fmt.Sprintf("/private/%s.key", name)
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil, errors.New("certificate not found")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return nil, errors.New("key not found")
	}

	log.Println("Reading certificate from:", certPath)
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	log.Println("Reading key from:", keyPath)
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	log.Println("Decoding certificate and key...")
	decodedCert, err := decodeCertificate(&cert)
	if err != nil {
		return nil, err
	}

	log.Println("Extracting certificate information...")
	serial, err := extractSerialNumber(decodedCert)
	if err != nil {
		return nil, err
	}

	subject, err := extractSubject(decodedCert)
	if err != nil {
		return nil, err
	}

	validity, err := extractValidity(decodedCert)
	if err != nil {
		return nil, err
	}

	log.Println("Loading private key...")
	var privKey *rsa.PrivateKey
	if passphrase != nil {
		log.Println("Private key is encrypted, decrypting...")
		privKey, err = loadEncryptedRSAKey(&key, *passphrase)
		if err != nil {
			return nil, err
		}
	} else {
		log.Println("Private key is not encrypted, loading...")
		privKey, err = loadRSAKey(&key)
		if err != nil {
			return nil, err
		}
	}

	return &Certificate{
		SerialNumber:        serial,
		Subject:             subject,
		Validity:            validity,
		IsCA:                decodedCert.IsCA,
		PrivateKey:          privKey,
		IsEncrypted:         passphrase != nil,
		EncryptedPrivateKey: &key,
		Object:              &CertificateObject{Certificate: cert, Key: *privKey},
		Path:                path,
		Template:            decodedCert,
	}, nil
}

func decodeCertificate(certPEM *[]byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(*certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

func extractSerialNumber(cert *x509.Certificate) (*big.Int, error) {
	serialNumber := cert.SerialNumber.String()
	serial := big.NewInt(0)
	serial.SetString(serialNumber, 10)

	return serial, nil
}

func extractSubject(cert *x509.Certificate) (*CertificateSubject, error) {
	subject := &CertificateSubject{}

	if len(cert.Subject.Organization) > 0 {
		subject.Organization = cert.Subject.Organization[0]
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		subject.OrganizationalUnit = cert.Subject.OrganizationalUnit[0]
	}
	subject.CommonName = cert.Subject.CommonName
	if len(cert.Subject.Country) > 0 {
		subject.Country = cert.Subject.Country[0]
	}
	if len(cert.Subject.Province) > 0 {
		subject.Province = cert.Subject.Province[0]
	}
	if len(cert.Subject.Locality) > 0 {
		subject.Locality = cert.Subject.Locality[0]
	}
	if len(cert.Subject.ExtraNames) > 0 {
		subject.EmailAddress = cert.Subject.ExtraNames[0].Value.(string)
	}

	return subject, nil
}

func extractValidity(cert *x509.Certificate) (*CertificateValidity, error) {
	validity := &CertificateValidity{
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}

	return validity, nil
}

func loadRSAKey(keyPEM *[]byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(*keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return key, nil
}

func loadEncryptedRSAKey(keyPEM *[]byte, passphrase string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(*keyPEM)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing encrypted private key")
	}

	key, err := Decrypt(block.Bytes, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %v", err)
	}

	return key, nil
}
