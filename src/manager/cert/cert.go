package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"
)

type Certificate struct {
	SerialNumber        *big.Int
	Subject             *CertificateSubject
	Validity            *CertificateValidity
	IsCA                bool
	IsRoot              *bool
	PrivateKey          *rsa.PrivateKey
	IsEncrypted         bool
	EncryptedPrivateKey *[]byte
	Object              *CertificateObject
	Path                string
	Template            *x509.Certificate
}

type CertificateSubject struct {
	Organization       string
	OrganizationalUnit string
	CommonName         string
	Country            string
	Province           string
	Locality           string
	EmailAddress       string
}

type CertificateObject struct {
	Certificate []byte
	Key         rsa.PrivateKey
}

type CertificateValidity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type CertificateAltNameOptions struct {
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
}

func NewCertificateSubject(organization, organizationalUnit, commonName, country, province, locality, emailAddress string) *CertificateSubject {
	return &CertificateSubject{
		Organization:       organization,
		OrganizationalUnit: organizationalUnit,
		CommonName:         commonName,
		Country:            country,
		Province:           province,
		Locality:           locality,
		EmailAddress:       emailAddress,
	}
}

func NewCertificateValidity(notBefore *time.Time, notAfter time.Time) *CertificateValidity {
	notBeforeTime := notBefore
	if notBefore == nil {
		now := time.Now()
		notBeforeTime = &now
	}
	return &CertificateValidity{
		NotBefore: *notBeforeTime,
		NotAfter:  notAfter,
	}
}

func NewCertificate(subject *CertificateSubject, validity *CertificateValidity, isCA bool, isRoot bool, serial *big.Int, path string) *Certificate {
	return &Certificate{
		SerialNumber: serial,
		Subject:      subject,
		Validity:     validity,
		IsCA:         isCA,
		IsRoot:       &isRoot,
		IsEncrypted:  isRoot,
		Path:         path,
	}
}

func (c *Certificate) GeneratePrivateKey(len *int, passphrase *string) error {
	keyLength := 4096
	if len != nil {
		keyLength = *len
	}
	log.Println("Generating private key...")
	privKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return err
	}
	c.PrivateKey = privKey

	if passphrase != nil {
		encryptedKey, err := Encrypt(privKey, *passphrase)
		if err != nil {
			return err
		}
		c.EncryptedPrivateKey = &encryptedKey
	}
	return nil
}

func (c *Certificate) GenerateCATemplate(isRoot bool, parent *Certificate) (*x509.Certificate, error) {
	template, err := c.GenerateBaseTemplate(parent)
	if err != nil {
		return nil, err
	}

	template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	c.Template = template
	return template, nil
}

func (c *Certificate) GenerateWebServerTemplate(parent *Certificate, altNames *CertificateAltNameOptions) (*x509.Certificate, error) {
	if parent != nil {
		log.Println("Generating web server certificate template...")
		log.Println("Parent certificate: ", parent.Subject.CommonName)
	}

	template, err := c.GenerateBaseTemplate(parent)
	if err != nil {
		return nil, err
	}

	template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment

	template, err = addAltNames(template, altNames)
	if err != nil {
		return nil, err
	}

	if parent != nil {
		template.AuthorityKeyId = parent.Template.SubjectKeyId
	}

	c.Template = template
	return template, nil
}

func (c *Certificate) GenerateBaseTemplate(parent *Certificate) (*x509.Certificate, error) {
	log.Println("Generating base certificate template...")
	template := &x509.Certificate{
		Subject: pkix.Name{
			Organization:       []string{c.Subject.Organization},
			OrganizationalUnit: []string{c.Subject.OrganizationalUnit},
			CommonName:         c.Subject.CommonName,
			Country:            []string{c.Subject.Country},
			Province:           []string{c.Subject.Province},
			Locality:           []string{c.Subject.Locality},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
					Value: c.Subject.EmailAddress,
				},
			},
		},
		NotBefore:             c.Validity.NotBefore,
		NotAfter:              c.Validity.NotAfter,
		IsCA:                  c.IsCA,
		BasicConstraintsValid: c.IsCA,
	}

	if c.SerialNumber != nil {
		template.SerialNumber = c.SerialNumber
	}

	if c.PrivateKey == nil {
		return nil, fmt.Errorf("private key is not available")
	}
	ski, err := generateSubjectKeyIdentifier(&c.PrivateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	template.SubjectKeyId = ski

	var aki []byte
	if parent != nil {
		aki = parent.Template.SubjectKeyId
	} else {
		aki = ski
	}
	akiExtension := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 35},
		Critical: false,
		Value:    append([]byte{0x30, 0x16, 0x80, 0x14}, aki...),
	}
	template.ExtraExtensions = append(template.ExtraExtensions, akiExtension)

	return template, nil
}

func (c *Certificate) SetKeyUsage(usages x509.KeyUsage) {
	c.Template.KeyUsage = usages
}

func (c *Certificate) SetExtraExtensions(extensions []pkix.Extension) {
	c.Template.ExtraExtensions = extensions
}

func addAltNames(template *x509.Certificate, altNames *CertificateAltNameOptions) (*x509.Certificate, error) {
	var rawValues []asn1.RawValue

	for _, dnsName := range altNames.DNSNames {
		rawValues = append(rawValues, asn1.RawValue{
			Tag:   2,
			Class: asn1.ClassContextSpecific,
			Bytes: []byte(dnsName),
		})
	}

	for _, ip := range altNames.IPAddresses {
		rawValues = append(rawValues, asn1.RawValue{
			Tag:   7,
			Class: asn1.ClassContextSpecific,
			Bytes: ip,
		})
	}

	for _, email := range altNames.EmailAddresses {
		rawValues = append(rawValues, asn1.RawValue{
			Tag:   1,
			Class: asn1.ClassContextSpecific,
			Bytes: []byte(email),
		})
	}

	sanBytes, err := asn1.Marshal(rawValues)
	if err != nil {
		return nil, err
	}

	sanExtension := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 17},
		Critical: false,
		Value:    sanBytes,
	}

	template.ExtraExtensions = append(template.ExtraExtensions, sanExtension)
	return template, nil
}

func generateSubjectKeyIdentifier(pubKey *rsa.PublicKey) ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	hash := sha1.Sum(pubKeyBytes)
	return hash[:], nil
}

func (c *Certificate) GenerateCertificate(template *x509.Certificate) (*CertificateObject, error) {
	log.Println("Generating self-signed certificate...")
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &c.PrivateKey.PublicKey, c.PrivateKey)
	if err != nil {
		return nil, err
	}

	c.Object = &CertificateObject{
		Certificate: cert,
		Key:         *c.PrivateKey,
	}
	if c.IsCA {
		c.NewSerial()
	}
	return c.Object, nil
}

func (c *Certificate) GenerateSignedCertificate(template *x509.Certificate, parent *x509.Certificate, pub interface{}, priv interface{}) (*CertificateObject, error) {
	log.Println("Generating signed certificate...")
	if template == nil {
		return nil, fmt.Errorf("template is nil")
	}
	if parent == nil {
		return nil, fmt.Errorf("parent certificate is nil")
	}

	template.AuthorityKeyId = parent.SubjectKeyId

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}

	return &CertificateObject{
		Certificate: certBytes,
		Key:         *priv.(*rsa.PrivateKey),
	}, nil
}

func (c *Certificate) SetIsRoot() {
	isRoot := true
	c.IsRoot = &isRoot
}
