package cert

import (
	"crypto/x509"
	"encoding/pem"
	"log"
)

func (o *CertificateObject) ExportAsPEM() (key *[]byte, cert *[]byte, format string) {
	privKeyPEM, err := x509.MarshalPKCS8PrivateKey(&o.Key)
	if err != nil {
		log.Fatalf("Failed to marshal private key: %v", err)
	}
	log.Println("Encoding private key to PEM format and storing it in memory...")
	keyOutput := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyPEM})

	log.Println("Encoding certificate to PEM format and storing it in memory...")
	certOutput := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: o.Certificate})

	return &keyOutput, &certOutput, "pem"
}

func (o *CertificateObject) ExportAsEncryptedPEM(passphrase string) (key *[]byte, cert *[]byte, format string) {
	log.Println("Encrypting private key...")
	encryptedKey, err := Encrypt(&o.Key, passphrase)
	if err != nil {
		log.Fatalf("Failed to encrypt private key: %v", err)
	}

	log.Println("Encoding encrypted private key to PEM format and storing it in memory...")
	keyOutput := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encryptedKey})

	log.Println("Encoding certificate to PEM format and storing it in memory...")
	certOutput := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: o.Certificate})

	return &keyOutput, &certOutput, "pem"
}
