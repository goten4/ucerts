package tls

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/goten4/ucerts/internal/format"
)

var (
	ErrGenerateKey          = errors.New("generate key")
	ErrGenerateSerialNumber = errors.New("generate serial number")
	ErrGenerateCert         = errors.New("generate cert")
	ErrCopyCA               = errors.New("copy CA")
)

func GenerateKey(req CertificateRequest) (crypto.PublicKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, ErrGenerateKey
	}

	pemKey := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	err = WritePemToFile(pemKey, req.OutKeyPath)
	if err != nil {
		return nil, err
	}

	return key.Public(), nil
}

func GenerateCertificate(req CertificateRequest, publicKey crypto.PublicKey) error {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf(format.WrapErrors, ErrGenerateSerialNumber, err)
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         req.CommonName,
			Country:            req.Countries,
			Organization:       req.Organizations,
			OrganizationalUnit: req.OrganizationalUnits,
			Locality:           req.Localities,
			Province:           req.Provinces,
			StreetAddress:      req.StreetAddresses,
			PostalCode:         req.PostalCodes,
		},
		SerialNumber: serialNumber,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(req.Duration),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  req.ExtKeyUsages,
		DNSNames:     req.DNSNames,
		IPAddresses:  req.IPAddresses,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caKey)
	if err != nil {
		return fmt.Errorf(format.WrapErrors, ErrGenerateCert, err)
	}

	pemCert := &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	err = WritePemToFile(pemCert, req.OutCertPath)
	if err != nil {
		return fmt.Errorf(format.WrapErrors, ErrGenerateCert, err)
	}

	return nil
}

func CopyCA(req CertificateRequest) error {
	pemCAFile, err := os.Create(req.OutCAPath)
	if err != nil {
		return fmt.Errorf(format.WrapErrors, ErrCopyCA, err)
	}
	defer pemCAFile.Close()

	pemCA := &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}
	err = pem.Encode(pemCAFile, pemCA)
	if err != nil {
		return fmt.Errorf(format.WrapErrors, ErrCopyCA, err)
	}

	return nil
}
