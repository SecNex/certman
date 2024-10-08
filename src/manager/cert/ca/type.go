package ca

import "github.com/secnex/certman/cert/manager/cert"

type CA struct {
	CustomerID  string
	AuthorityID string
	Path        string
	Certificate *cert.Certificate
	Passphrase  *string
}
