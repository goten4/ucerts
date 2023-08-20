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
	"strings"
	"time"

	"github.com/goten4/ucerts/internal/format"
)

type Issuer struct {
	PublicKey  *x509.Certificate
	PrivateKey crypto.PrivateKey
}

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

func GeneratePrivateKey(req CertificateRequest) (crypto.PrivateKey, error) {
	algorithm := req.PrivateKey.Algorithm
	if algorithm == "" {
		algorithm = RSA
	}

	var key crypto.PrivateKey
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

var generateRSAPrivateKey = func(req CertificateRequest) (crypto.PrivateKey, *pem.Block, error) {
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
	return key, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}, nil
}

var generateECPrivateKey = func(req CertificateRequest) (crypto.PrivateKey, *pem.Block, error) {
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

	return key, &pem.Block{Type: "EC PRIVATE KEY", Bytes: bytes}, nil
}

var generateEd25519PrivateKey = func(req CertificateRequest) (crypto.PrivateKey, *pem.Block, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf(format.WrapErrors, ErrEncodePrivateKey, err)
	}

	return key, &pem.Block{Type: "PRIVATE KEY", Bytes: bytes}, nil
}

func GenerateCertificate(req CertificateRequest, key crypto.PrivateKey, issuer *Issuer) error {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf(format.WrapErrors, ErrGenerateSerialNumber, err)
	}

	// All certificates should have the DigitalSignature KeyUsage bits set.
	keyUsage := x509.KeyUsageDigitalSignature
	// RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.
	if _, isRSA := key.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	// If certificate is a CA, force CertSign usage
	if req.IsCA {
		keyUsage |= x509.KeyUsageCertSign
	}

	notBefore := time.Now()
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
		SerialNumber:          serialNumber,
		IsCA:                  req.IsCA,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(req.Duration),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           req.ExtKeyUsage,
		DNSNames:              req.DNSNames,
		IPAddresses:           req.IPAddresses,
		BasicConstraintsValid: true,
	}

	// Default is selfsigned
	issuerCert := template
	signerKey := key
	if issuer != nil {
		issuerCert = issuer.PublicKey
		signerKey = issuer.PrivateKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, issuerCert, publicKey(key), signerKey)
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

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func CopyCA(issuer *Issuer, path string) error {
	pemCert := &pem.Block{Type: "CERTIFICATE", Bytes: issuer.PublicKey.Raw}
	err := WritePemToFile(pemCert, path)
	if err != nil {
		return fmt.Errorf(format.WrapErrors, ErrCopyCA, err)
	}
	return nil
}
