package ca

import (
	"log"
	"os"

	"github.com/secnex/certman/cert/manager/cert"
)

func Load(customerID string, authorityID string, passphrase *string, path string, alias string, intermediate bool) *CA {
	if intermediate {
		path = path + "/intermediate"
	} else {
		path = preparePath(customerID, authorityID, path)
	}
	log.Println("Loading CA from:", path)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	cert, err := cert.LoadCertificate(path, alias, passphrase)
	if err != nil {
		return nil
	}

	return &CA{
		CustomerID:  customerID,
		AuthorityID: authorityID,
		Path:        path,
		Passphrase:  passphrase,
		Certificate: cert,
	}
}
