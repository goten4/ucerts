package tls

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
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

func LoadCertificateRequests(dir string) {
	files, err := ReadDir(dir)
	if err != nil {
		logger.Errorf("Failed to read directory %s: %v", dir, err)
		return
	}
	for _, file := range files {
		HandleCertificateRequestFile(file)
	}
}

func HandleCertificateRequestFile(file string) {
	logger.Printf("Handle certificate request %s", file)
	req, err := LoadCertificateRequest(file)
	if err != nil {
		return
	}

	if FileDoesNotExists(req.OutCertPath) {
		if ok := MakeParentsDirectories(req.OutCertPath); !ok {
			return
		}
		GenerateOutFilesFromRequest(req)
		return
	}

	cert, err := LoadCertFromFile(req.OutCertPath)
	if err != nil {
		logger.Errorf("Invalid certificate %s: %v", req.OutCertPath, err)
		GenerateOutFilesFromRequest(req)
		return
	}

	if cert.NotAfter.After(time.Now()) {
		logger.Printf("Expired certificate %s", req.OutCertPath, err)
		GenerateOutFilesFromRequest(req)
		return
	}
}

func GenerateOutFilesFromRequest(req CertificateRequest) {
	logger.Errorf("Generate key %s", req.OutKeyPath)
	publicKey, err := GenerateKey(req)
	if err != nil {
		logError(err)
		return
	}

	logger.Errorf("Generate certificate %s", req.OutCertPath)
	if err := GenerateCertificate(req, publicKey); err != nil {
		logError(err)
		return
	}

	logger.Errorf("Copy CA to %s", req.OutCAPath)
	if err := CopyCA(req); err != nil {
		logError(err)
		return
	}
}

func logError(err error) {
	logger.Errorf("Failure: %v", err)
}
