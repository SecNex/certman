package ca

import (
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/secnex/certman/manager/cert"
)

func New(customerID string, passphrase *string, path string) *CA {
	authorityID := uuid.New().String()
	path = preparePath(customerID, authorityID, path)

	cert.CreateFolderStructure(path)

	return &CA{
		CustomerID:  customerID,
		AuthorityID: authorityID,
		Path:        path,
		Passphrase:  passphrase,
	}
}

func (ca *CA) Generate(organization string, organizationalUnit string, commonName string, country string, province string, locality string, emailAddress string) error {
	subject := cert.NewCertificateSubject(organization, organizationalUnit, commonName, country, province, locality, emailAddress)
	validity := cert.NewCertificateValidity(nil, time.Now().AddDate(10, 0, 0))
	ca.Certificate = cert.NewCertificate(subject, validity, true, true, big.NewInt(1), ca.Path)
	if err := ca.Certificate.GeneratePrivateKey(nil, ca.Passphrase); err != nil {
		return err
	}

	template, err := ca.Certificate.GenerateCATemplate(true, nil)
	if err != nil {
		return err
	}

	certCA, err := ca.Certificate.GenerateCertificate(template)
	if err != nil {
		return err
	}

	key, certificate, format := certCA.ExportAsEncryptedPEM(*ca.Passphrase)
	if key == nil || certificate == nil {
		return fmt.Errorf("error exporting certificate")
	}

	return cert.SaveCertificate(key, certificate, format, ca.Path, "root")
}
