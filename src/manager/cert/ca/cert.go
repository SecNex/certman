package ca

import (
	"fmt"
	"time"

	"github.com/secnex/certman/cert/manager/cert"
)

func (ca *CA) CreateSubCA(organization string, organizationalUnit string, commonName string, country string, province string, locality string, emailAddress string) *cert.Certificate {
	serial := ca.Certificate.GetSerial(false)

	path := fmt.Sprintf("%s/intermediate", ca.Path)

	cert.CreateFolderStructure(path)

	subject := cert.NewCertificateSubject(organization, organizationalUnit, commonName, country, province, locality, emailAddress)
	validity := cert.NewCertificateValidity(nil, time.Now().AddDate(5, 0, 0))
	intermediate := cert.NewCertificate(subject, validity, true, false, &serial, path)
	if err := intermediate.GeneratePrivateKey(nil, ca.Passphrase); err != nil {
		panic(err)
	}

	intermediateTemplate, err := intermediate.GenerateCATemplate(false, ca.Certificate)
	if err != nil {
		panic(err)
	}

	subCA, err := intermediate.GenerateSignedCertificate(
		intermediateTemplate,
		ca.Certificate.Template,
		&ca.Certificate.PrivateKey.PublicKey,
		ca.Certificate.PrivateKey,
	)
	if err != nil {
		panic(err)
	}

	key, certificate, format := subCA.ExportAsEncryptedPEM(*ca.Passphrase)
	if key == nil || certificate == nil {
		panic(fmt.Errorf("error exporting certificate"))
	}

	if err := cert.SaveCertificate(key, certificate, format, intermediate.Path, "intermediate"); err != nil {
		panic(err)
	}

	return intermediate
}
