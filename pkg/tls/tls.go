package tls

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/goten4/ucerts/internal/config"
	"github.com/goten4/ucerts/internal/logger"
)

var (
	ca                 *x509.Certificate
	caKey              crypto.PrivateKey
	ErrInvalidPEMBlock = errors.New("invalid PEM block")
)

func Init() {
	rootCA, err := tls.LoadX509KeyPair(config.CAPath, config.CAKeyPath)
	if err != nil {
		logger.Failf("Failed to load CA key pair: %v", err)
		return
	}
	caKey = rootCA.PrivateKey
	ca, err = x509.ParseCertificate(rootCA.Certificate[0])
	if err != nil {
		logger.Failf("Failed to parse CA: %v", err)
		return
	}
}

func LoadConfigs(dir string) {
	for _, file := range readDir(dir) {
		Load(file)
	}
}

func readDir(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		logger.Errorf("Failed to read directory %s: %v", dir, err)
		return []string{}
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		info, _ := entry.Info()
		if !info.IsDir() {
			files = append(files, filepath.Join(dir, info.Name()))
		}
	}
	return files
}

func Load(path string) {
	conf, err := LoadConfig(path)
	if err != nil {
		return
	}

	if _, err := os.Stat(conf.OutCertPath); errors.Is(err, os.ErrNotExist) {
		if ok := createDirectoryIfNecessary(conf.OutCertPath); !ok {
			return
		}
		if ok := createDirectoryIfNecessary(conf.OutKeyPath); !ok {
			return
		}
		GenerateCertificate(conf)
		return
	}

	cert, err := loadCert(conf.OutCertPath)
	if err != nil {
		logger.Errorf("Invalid certificate %s: %v", conf.OutCertPath, err)
		GenerateCertificate(conf)
		return
	}

	if cert.NotAfter.After(time.Now()) {
		logger.Printf("Expired certificate %s", conf.OutCertPath, err)
		GenerateCertificate(conf)
		return
	}
}

func createDirectoryIfNecessary(path string) bool {
	dir := filepath.Dir(path)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return false
		}
	}
	return true
}

func GenerateCertificate(conf Config) {
	logger.Printf("Generate certificate %s", conf.OutCertPath)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logger.Errorf("Failed to generate serial number: %v", err)
		return
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         conf.CommonName,
			Country:            conf.Countries,
			Organization:       conf.Organizations,
			OrganizationalUnit: conf.OrganizationalUnits,
			Locality:           conf.Localities,
			Province:           conf.Provinces,
			StreetAddress:      conf.StreetAddresses,
			PostalCode:         conf.PostalCodes,
		},
		SerialNumber: serialNumber,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(conf.Duration),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  conf.ExtKeyUsages,
		DNSNames:     conf.DNSNames,
		IPAddresses:  conf.IPAddresses,
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		logger.Errorf("Failed to generate private key: %v", err)
		return
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
	if err != nil {
		logger.Errorf("Failed to create certificate: %v", err)
		return
	}

	pemCertFile, err := os.Create(conf.OutCertPath)
	if err != nil {
		logger.Errorf("Failed to create certificate file handler %s: %v", conf.OutCertPath, err)
		return
	}
	defer pemCertFile.Close()
	pemCert := &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	err = pem.Encode(pemCertFile, pemCert)
	if err != nil {
		logger.Errorf("Failed to write certificate to file %s: %v", conf.OutCertPath, err)
		return
	}

	pemKeyFile, err := os.Create(conf.OutKeyPath)
	if err != nil {
		logger.Errorf("Failed to create key file handler %s: %v", conf.OutKeyPath, err)
		return
	}
	defer pemKeyFile.Close()
	pemKey := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	err = pem.Encode(pemKeyFile, pemKey)
	if err != nil {
		logger.Errorf("Failed to write key to file %s: %v", conf.OutKeyPath, err)
		return
	}
}

func loadCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	certPEMBlock, _ := pem.Decode(b)
	if certPEMBlock == nil || certPEMBlock.Type != "CERTIFICATE" {
		return nil, ErrInvalidPEMBlock
	}

	x509Cert, err := x509.ParseCertificate(certPEMBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return x509Cert, nil
}
