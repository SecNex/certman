package manager

import (
	"fmt"

	"github.com/secnex/certman/manager/cert"
	"github.com/secnex/certman/manager/cert/ca"
)

func CreateIntermediateCA(rootCA *ca.CA, organization string, organizationalUnit string, commonName string, country string, province string, locality string, emailAddress string) *cert.Certificate {
	return rootCA.CreateSubCA(
		organization,
		organizationalUnit,
		commonName,
		country,
		province,
		locality,
		emailAddress,
	)
}

func LoadIntermediateCA(customerID string, authorityID string, passphrase *string, path string, name string) *ca.CA {
	p := fmt.Sprintf("%s/%s/%s", path, customerID, authorityID)
	return ca.Load(customerID, authorityID, passphrase, p, name, true)
}
