package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/secnex/certman/provider/store"
)

type Certificate struct {
	AuthorityID    *string
	OrganizationId string
	Information    CertificateInformation
	PrivateKey     *rsa.PrivateKey
	CACertificate  *x509.Certificate
	CAPrivateKey   *rsa.PrivateKey
	IsCA           bool
	IsRoot         bool
	KeyLength      *int
	SerialNumber   *big.Int
	Certificate    *x509.Certificate
	Storage        *store.Storage
}

type CertificateInformation struct {
	Subject    *CertificateSubject
	Validity   *CertificateValidity
	Extensions *CertificateExtensions
}

type CertificateSubject struct {
	Organization       string
	OrganizationalUnit *string
	CommonName         string
	Country            string
	StreetAddress      *string
	PostalCode         *string
	StateOrProvince    *string
	Locality           *string
	EmailAddress       *string
}

type CertificateValidity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type CertificateExtensions struct {
	BasicConstraintsValid bool
	SubjectAltName        *CertificateSubjectAltName
}

type CertificateSubjectAltName struct {
	DNSNames       *[]string
	EmailAddresses *[]string
	IPAddresses    *[]string
}

func NewCertificateSubject(organization string, organizationalUnit *string, commonName string, country string, streetAddress *string, postalCode *string, stateOrProvince *string, locality *string, emailAddress *string) *CertificateSubject {
	return &CertificateSubject{
		Organization:       organization,
		OrganizationalUnit: organizationalUnit,
		CommonName:         commonName,
		Country:            country,
		StreetAddress:      streetAddress,
		PostalCode:         postalCode,
		StateOrProvince:    stateOrProvince,
		Locality:           locality,
		EmailAddress:       emailAddress,
	}
}

func NewCertificateValidity(notBefore *time.Time, notAfter *time.Time) *CertificateValidity {
	var notBeforeTime, notAfterTime time.Time
	if notBefore == nil {
		notBeforeTime = time.Now()
	} else {
		notBeforeTime = *notBefore
	}
	if notAfter == nil {
		notAfterTime = notBeforeTime.AddDate(1, 0, 0)
	} else {
		notAfterTime = *notAfter
	}
	return &CertificateValidity{
		NotBefore: notBeforeTime,
		NotAfter:  notAfterTime,
	}
}

func NewCertificateExtensions(basicConstraintsValid bool, subjectAltName *CertificateSubjectAltName) *CertificateExtensions {
	return &CertificateExtensions{
		BasicConstraintsValid: basicConstraintsValid,
		SubjectAltName:        subjectAltName,
	}
}

func NewCertificateSubjectAltName(dnsNames *[]string, emailAddresses *[]string, ipAddresses *[]string) *CertificateSubjectAltName {
	return &CertificateSubjectAltName{
		DNSNames:       dnsNames,
		EmailAddresses: emailAddresses,
		IPAddresses:    ipAddresses,
	}
}

func NewCertificateInformation(subject *CertificateSubject, validity *CertificateValidity, extensions *CertificateExtensions) CertificateInformation {
	return CertificateInformation{
		Subject:    subject,
		Validity:   validity,
		Extensions: extensions,
	}
}

func NewCertificate(authorityID *string, organizationId string, information CertificateInformation, privateKey *rsa.PrivateKey, certificate *x509.Certificate, serialNumber *big.Int, keyLength *int, isCA *bool, isRoot *bool) (*Certificate, error) {
	IsCA := false
	IsRoot := false
	authority := ""
	serialNum := big.NewInt(1)
	keyLen := 4096

	if isCA != nil {
		IsCA = *isCA
	}

	if isRoot != nil {
		IsRoot = *isRoot
	}

	if IsRoot {
		IsCA = true
	}

	if serialNumber != nil {
		serialNum = serialNumber
	}

	if keyLength != nil {
		keyLen = *keyLength
	}

	if !IsRoot && privateKey == nil {
		return nil, fmt.Errorf("private key is required for CA certificates")
	}

	return &Certificate{
		AuthorityID:    &authority,
		OrganizationId: organizationId,
		Information:    information,
		CACertificate:  certificate,
		CAPrivateKey:   privateKey,
		IsCA:           IsCA,
		IsRoot:         IsRoot,
		SerialNumber:   serialNum,
		KeyLength:      &keyLen,
	}, nil
}

func (s *CertificateSubject) ToPKIXName() pkix.Name {
	subject := pkix.Name{
		Organization: []string{s.Organization},
		CommonName:   s.CommonName,
		Country:      []string{s.Country},
		ExtraNames:   []pkix.AttributeTypeAndValue{},
	}
	if s.OrganizationalUnit != nil {
		subject.OrganizationalUnit = []string{*s.OrganizationalUnit}
	}
	if s.StreetAddress != nil {
		subject.StreetAddress = []string{*s.StreetAddress}
	}
	if s.PostalCode != nil {
		subject.PostalCode = []string{*s.PostalCode}
	}
	if s.StateOrProvince != nil {
		subject.Province = []string{*s.StateOrProvince}
	}
	if s.Locality != nil {
		subject.Locality = []string{*s.Locality}
	}
	if s.EmailAddress != nil {
		subject.ExtraNames = append(subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type:  []int{1, 2, 840, 113549, 1, 9, 1},
			Value: *s.EmailAddress,
		})
	}

	return subject
}

func (c *Certificate) Create() (*x509.Certificate, error) {
	template := &x509.Certificate{
		Subject:         c.Information.Subject.ToPKIXName(),
		NotBefore:       c.Information.Validity.NotBefore,
		NotAfter:        c.Information.Validity.NotAfter,
		SerialNumber:    big.NewInt(1),
		Extensions:      []pkix.Extension{},
		ExtraExtensions: []pkix.Extension{},
	}

	if c.CACertificate == nil || c.CAPrivateKey == nil {
		log.Println("Certificate authority is not set!")
	}

	if c.IsRoot {
		log.Println("Creating a root CA certificate...")
		template.IsCA = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
		template.BasicConstraintsValid = true
		template.MaxPathLen = -1

		log.Println("Key Usage:", template.KeyUsage)

		privKey, err := rsa.GenerateKey(rand.Reader, *c.KeyLength)
		if err != nil {
			return nil, err
		}

		template.PublicKey = privKey.Public()
		c.PrivateKey = privKey
		c.CAPrivateKey = privKey

		ski, err := generateSubjectKeyIdentifier(&privKey.PublicKey)
		if err != nil {
			return nil, err
		}
		template.SubjectKeyId = ski

		aki, err := generateAuthorityKeyIdentifier(&privKey.PublicKey)
		if err != nil {
			return nil, err
		}
		akiExtension := pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 35}, // OID for authorityKeyIdentifier
			Critical: false,
			Value:    append([]byte{0x30, 0x16, 0x80, 0x14}, aki...), // keyid:always,issuer
		}
		template.ExtraExtensions = append(template.ExtraExtensions, akiExtension)
	} else {
		log.Println("Creating a certificate...")
		template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature

		log.Println("Key Usage:", template.KeyUsage)

		if c.IsCA {
			log.Println("Creating a intermediate CA certificate...")
			template.IsCA = true
			template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
			template.BasicConstraintsValid = true
			template.MaxPathLen = 0
		}

		log.Println("Key Usage:", template.KeyUsage)

		template.SerialNumber = c.SerialNumber

		privKey, err := rsa.GenerateKey(rand.Reader, *c.KeyLength)
		if err != nil {
			return nil, err
		}
		template.PublicKey = privKey.Public()
		c.PrivateKey = privKey

		aki, err := generateAuthorityKeyIdentifier(&c.CAPrivateKey.PublicKey)
		if err != nil {
			return nil, err
		}

		log.Printf("Authority Key Identifier: %x", aki)

		akiExtension := pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 35}, // OID for authorityKeyIdentifier
			Critical: false,
			Value:    append([]byte{0x30, 0x16, 0x80, 0x14}, aki...), // keyid:always,issuer
		}
		template.ExtraExtensions = append(template.ExtraExtensions, akiExtension)

		ski, err := generateSubjectKeyIdentifier(&privKey.PublicKey)
		if err != nil {
			return nil, err
		}

		log.Printf("Subject Key Identifier: %x", ski)

		template.SubjectKeyId = ski
	}

	if c.Information.Extensions.BasicConstraintsValid {
		template.BasicConstraintsValid = true
	}

	if c.Information.Extensions.SubjectAltName != nil {
		if c.Information.Extensions.SubjectAltName.DNSNames != nil {
			template.DNSNames = *c.Information.Extensions.SubjectAltName.DNSNames
		}
		if c.Information.Extensions.SubjectAltName.EmailAddresses != nil {
			template.EmailAddresses = *c.Information.Extensions.SubjectAltName.EmailAddresses
		}
		if c.Information.Extensions.SubjectAltName.IPAddresses != nil {
			for _, ip := range *c.Information.Extensions.SubjectAltName.IPAddresses {
				template.IPAddresses = append(template.IPAddresses, net.ParseIP(ip))
				log.Printf("IP Address: %s", ip)
			}
		}
	}

	c.Certificate = template

	return template, nil
}

func (c *Certificate) Sign() ([]byte, error) {
	log.Println("Signing certificate...")
	var parent *x509.Certificate
	var parentKey *rsa.PrivateKey

	if c.CACertificate != nil {
		log.Println("Using CA certificate to sign certificate...")
		parent = c.CACertificate
		parentKey = c.CAPrivateKey
		log.Println("CA Identifier:", c.CACertificate.SubjectKeyId)
		log.Println("Certificate Identifier:", c.Certificate.SubjectKeyId)
	} else {
		log.Println("Using self-signed certificate to sign certificate...")
		parent = c.Certificate
		parentKey = c.PrivateKey
		log.Println("Certificate Identifier:", c.Certificate.SubjectKeyId)
	}

	// Log the public keys to ensure they match
	log.Printf("Parent Public Key: %x", parent.PublicKey.(*rsa.PublicKey).N)
	log.Printf("Certificate Public Key: %x", c.Certificate.PublicKey.(*rsa.PublicKey).N)

	// Check if the provided private key matches the parent's public key
	if parentKey.PublicKey.N.Cmp(parent.PublicKey.(*rsa.PublicKey).N) != 0 {
		return nil, fmt.Errorf("provided PrivateKey doesn't match parent's PublicKey")
	}

	cert, err := x509.CreateCertificate(rand.Reader, c.Certificate, parent, &c.PrivateKey.PublicKey, parentKey)
	if err != nil {
		log.Println("Failed to sign certificate!")
		return nil, err
	}
	log.Println("Certificate signed successfully!")
	return cert, nil
}
