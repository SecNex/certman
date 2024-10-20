package template

import (
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/secnex/certman/cert"
	"github.com/secnex/certman/provider/store"
)

func NewWebsiteCertificate(subject *cert.CertificateSubject, san *cert.CertificateSubjectAltName, storage store.Storage, authority string) (*string, error) {
	log.Printf("Creating website certificate with CA %s...", authority)
	identifier := uuid.New().String()
	isCA := false
	isRoot := false
	notAfter := time.Now().AddDate(1, 0, 0)
	validity := cert.NewCertificateValidity(nil, &notAfter)
	extensions := cert.NewCertificateExtensions(false, san)
	certInfos := cert.NewCertificateInformation(subject, validity, extensions)

	// Laden des CA-Zertifikats und des privaten Schlüssels
	caCertBytes, err := storage.Provider.Get(fmt.Sprintf("%s.pem", authority))
	if err != nil {
		log.Println("Failed to get certificate!")
		return nil, err
	}
	caKeyBytes, err := storage.Provider.Get(fmt.Sprintf("%s.key", authority))
	if err != nil {
		log.Println("Failed to get private key!")
		return nil, err
	}

	// Dekodieren des CA-Zertifikats und des privaten Schlüssels
	caCert, err := cert.DecodeCertificate(caCertBytes)
	if err != nil {
		log.Println("Failed to decode certificate!")
		return nil, err
	}
	caKey, err := cert.DecodePrivateKey(caKeyBytes)
	if err != nil {
		log.Println("Failed to decode private key!")
		return nil, err
	}

	// Generieren der Seriennummer
	serial, err := cert.GenerateSerialNumber()
	if err != nil {
		log.Println("Failed to generate serial number!")
		return nil, err
	}

	keyLength := 2048
	// Erstellen des neuen Zertifikats
	c, err := cert.NewCertificate(
		nil,
		identifier,
		certInfos,
		caKey,
		caCert,
		serial,
		&keyLength,
		&isCA,
		&isRoot,
	)
	if err != nil {
		log.Println("Failed to create certificate!")
		return nil, err
	}

	// Erstellen des Zertifikats
	cert, err := c.Create()
	if err != nil {
		log.Println("Failed to create certificate!")
		return nil, err
	}
	log.Println("Certificate created successfully!")

	log.Printf("NotBefore: %s", cert.Subject.SerialNumber)

	// Ausgabe des Zertifikats und des privaten Schlüssels
	certPEM, keyPEM, err := c.Output(nil)
	if err != nil {
		log.Println("Failed to output certificate!")
		return nil, err
	}

	// Speichern des Zertifikats und des privaten Schlüssels
	fileCert := fmt.Sprintf("%s.pem", identifier)
	fileKey := fmt.Sprintf("%s.key", identifier)
	if err := storage.Provider.New(fileCert, certPEM); err != nil {
		return nil, err
	}
	if err := storage.Provider.New(fileKey, keyPEM); err != nil {
		return nil, err
	}

	return &identifier, nil
}
