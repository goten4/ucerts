package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/goten4/ucerts/internal/format"
)

type GeneratePrivateKeyFunc func(int) (crypto.PrivateKey, error)

const (
	MinRSAKeySize = 2048
	MaxRSAKeySize = 8192
	RSA           = "rsa"
	ECDSA         = "ecdsa"
	ED25519       = "ed25519"
)

var (
	ErrGenerateKey                    = errors.New("generate key")
	ErrGenerateSerialNumber           = errors.New("generate serial number")
	ErrGenerateCert                   = errors.New("generate cert")
	ErrCopyCA                         = errors.New("copy CA")
	ErrRSAKeySizeTooWeak              = fmt.Errorf("RSA key size too weak, minimum is %d", MinRSAKeySize)
	ErrRSAKeySizeTooBig               = fmt.Errorf("RSA key size too big, maximum is %d", MaxRSAKeySize)
	ErrUnsupportedPrivateKeyAlgorithm = fmt.Errorf("unsupported private key algorithm")
	ErrEncodePrivateKey               = fmt.Errorf("encode private key")
	ErrUnsupportedECDSAKeySize        = errors.New("unsupported ecdsa key size")
)

func GeneratePrivateKey(req CertificateRequest) (crypto.PublicKey, error) {
	algorithm := req.PrivateKey.Algorithm
	if algorithm == "" {
		algorithm = RSA
	}

	var key crypto.PublicKey
	var pemBlock *pem.Block
	var err error

	switch strings.ToLower(algorithm) {
	case RSA:
		key, pemBlock, err = generateRSAPrivateKey(req)
	case ECDSA:
		key, pemBlock, err = generateECPrivateKey(req)
	case ED25519:
		key, pemBlock, err = generateEd25519PrivateKey(req)
	default:
		return nil, fmt.Errorf(format.WrapErrorString, ErrUnsupportedPrivateKeyAlgorithm, algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf(format.WrapErrors, ErrGenerateKey, err)
	}

	err = WritePemToFile(pemBlock, req.OutKeyPath)
	if err != nil {
		return nil, fmt.Errorf(format.WrapErrors, ErrGenerateKey, err)
	}

	return key, nil
}

var generateRSAPrivateKey = func(req CertificateRequest) (crypto.PublicKey, *pem.Block, error) {
	keySize := req.PrivateKey.Size
	if keySize == 0 {
		keySize = MinRSAKeySize
	}
	if keySize < MinRSAKeySize {
		return nil, nil, ErrRSAKeySizeTooWeak
	}
	if keySize > MaxRSAKeySize {
		return nil, nil, ErrRSAKeySizeTooBig
	}
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, err
	}
	return key.Public(), &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}, nil
}

var generateECPrivateKey = func(req CertificateRequest) (crypto.PublicKey, *pem.Block, error) {
	keySize := req.PrivateKey.Size
	if keySize == 0 {
		keySize = 256
	}

	var ecCurve elliptic.Curve
	switch keySize {
	case 256:
		ecCurve = elliptic.P256()
	case 384:
		ecCurve = elliptic.P384()
	case 521:
		ecCurve = elliptic.P521()
	default:
		return nil, nil, fmt.Errorf(format.WrapErrorInt, ErrUnsupportedECDSAKeySize, keySize)
	}

	key, err := ecdsa.GenerateKey(ecCurve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	bytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf(format.WrapErrors, ErrEncodePrivateKey, err)
	}

	return key.Public(), &pem.Block{Type: "EC PRIVATE KEY", Bytes: bytes}, nil
}

var generateEd25519PrivateKey = func(req CertificateRequest) (crypto.PublicKey, *pem.Block, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf(format.WrapErrors, ErrEncodePrivateKey, err)
	}

	return key.Public(), &pem.Block{Type: "PRIVATE KEY", Bytes: bytes}, nil
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
