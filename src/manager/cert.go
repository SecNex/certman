package manager

import (
	"log"
	"net"
	"time"

	"github.com/secnex/certman/manager/cert"
	"github.com/secnex/certman/manager/cert/ca"
)

func GenerateWebServerCert(ca *ca.CA, organization string, organizationalUnit string, commonName string, country string, province string, locality string, emailAddress string, dnsNames []string, ipAddresses []string, name string) *cert.Certificate {
	serial := ca.Certificate.GetSerial(true)
	webSubject := cert.NewCertificateSubject(organization, organizationalUnit, commonName, country, province, locality, emailAddress)
	webValidity := cert.NewCertificateValidity(nil, time.Now().AddDate(1, 0, 0))
	web := cert.NewCertificate(webSubject, webValidity, false, false, &serial, ca.Path)
	if err := web.GeneratePrivateKey(nil, nil); err != nil {
		panic(err)
	}

	ipAddressesParsed := make([]net.IP, len(ipAddresses))
	for i, ip := range ipAddresses {
		ipAddressesParsed[i] = net.ParseIP(ip)
	}
	webTemplate, err := web.GenerateWebServerTemplate(ca.Certificate, &cert.CertificateAltNameOptions{
		DNSNames:    []string{"haos.secnex.local"},
		IPAddresses: ipAddressesParsed,
	})
	if err != nil {
		panic(err)
	}

	if webTemplate == nil {
		panic("error creating web server template")
	}

	if web.PrivateKey == nil {
		panic("error creating private key")
	}

	log.Println("Generating web server certificate...")
	webCert, err := web.GenerateSignedCertificate(
		webTemplate,
		ca.Certificate.Template,
		&ca.Certificate.PrivateKey.PublicKey,
		ca.Certificate.PrivateKey,
	)

	if err != nil {
		panic(err)
	}

	log.Println("Exporting web server certificate...")
	key, certificate, format := webCert.ExportAsPEM()
	if key == nil || certificate == nil {
		panic("error exporting certificate")
	}

	log.Println("Saving web server certificate...")
	if err := cert.SaveCertificate(key, certificate, format, web.Path, name); err != nil {
		panic(err)
	}

	return web
}
