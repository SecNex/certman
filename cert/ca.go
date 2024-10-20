package cert

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/secnex/certman/provider/store"
)

func NewRootCA(subject *CertificateSubject, organizationId string, storage store.Storage) (*string, error) {
	identifier := uuid.New().String()
	isCA := true
	isRoot := true
	notAfter := time.Now().AddDate(30, 0, 0)
	validity := NewCertificateValidity(nil, &notAfter)
	extensions := NewCertificateExtensions(true, nil)
	certInfos := NewCertificateInformation(subject, validity, extensions)
	c, err := NewCertificate(
		nil,
		organizationId,
		certInfos,
		nil,
		nil,
		nil,
		nil,
		&isCA,
		&isRoot,
	)
	if err != nil {
		return nil, err
	}

	c.Create()
	__cert, __key, err := c.Output(nil)
	if err != nil {
		return nil, err
	}
	fileCert := fmt.Sprintf("%s.pem", identifier)
	fileKey := fmt.Sprintf("%s.key", identifier)
	if err := storage.Provider.New(fileCert, __cert); err != nil {
		return nil, err
	}
	if err := storage.Provider.New(fileKey, __key); err != nil {
		return nil, err
	}

	return &identifier, nil
}

func NewIntermediateCA(subject *CertificateSubject, organizationId string, storage store.Storage, authority string) (*string, error) {
	identifier := uuid.New().String()
	isCA := true
	isRoot := false
	notAfter := time.Now().AddDate(10, 0, 0)
	validity := NewCertificateValidity(nil, &notAfter)
	extensions := NewCertificateExtensions(true, nil)
	certInfos := NewCertificateInformation(subject, validity, extensions)
	__rootCACertByte, err := storage.Provider.Get(fmt.Sprintf("%s.pem", authority))
	if err != nil {
		return nil, err
	}
	__rootCAKeyByte, err := storage.Provider.Get(fmt.Sprintf("%s.key", authority))
	if err != nil {
		return nil, err
	}
	rootCACert, err := DecodeCertificate(__rootCACertByte)
	if err != nil {
		return nil, err
	}
	rootCAKey, err := DecodePrivateKey(__rootCAKeyByte)
	if err != nil {
		return nil, err
	}
	serial, err := GenerateSerialNumber()
	if err != nil {
		return nil, err
	}
	c, err := NewCertificate(
		nil,
		organizationId,
		certInfos,
		rootCAKey,
		rootCACert,
		serial,
		nil,
		&isCA,
		&isRoot,
	)
	if err != nil {
		return nil, err
	}

	c.Create()
	__cert, __key, err := c.Output(nil)
	if err != nil {
		return nil, err
	}
	fileCert := fmt.Sprintf("%s.pem", identifier)
	fileKey := fmt.Sprintf("%s.key", identifier)
	if err := storage.Provider.New(fileCert, __cert); err != nil {
		return nil, err
	}
	if err := storage.Provider.New(fileKey, __key); err != nil {
		return nil, err
	}

	return &identifier, nil
}
