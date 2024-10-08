package manager

import (
	"github.com/secnex/certman/cert/manager/cert/ca"
)

func CreateRootCA(customerID string, passphrase *string, path string, organization string, organizationalUnit string, commonName string, country string, province string, locality string, emailAddress string) *string {
	root := ca.New(customerID, passphrase, path)
	if root == nil {
		return nil
	}
	root.Generate(
		organization,
		organizationalUnit,
		commonName,
		country,
		province,
		locality,
		emailAddress,
	)
	return &root.AuthorityID
}

func LoadRootCA(customerID string, authorityID string, passphrase *string, path string, name string) *ca.CA {
	return ca.Load(customerID, authorityID, passphrase, path, name, false)
}
