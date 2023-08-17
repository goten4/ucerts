package tls

import (
	"errors"
	"time"

	"github.com/goten4/ucerts/internal/logger"
)

var (
	ErrInvalidPEMBlock = errors.New("invalid PEM block")
)

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

	issuer, err := LoadIssuer(req.IssuerPath)
	if err != nil {
		logger.Errorf("Invalid issuer: %v", err)
		return
	}

	if FileDoesNotExists(req.OutCertPath) {
		if ok := MakeParentsDirectories(req.OutCertPath); !ok {
			return
		}
		GenerateOutFilesFromRequest(req, issuer)
		return
	}

	cert, err := LoadCertFromFile(req.OutCertPath)
	if err != nil {
		logger.Errorf("Invalid certificate %s: %v", req.OutCertPath, err)
		GenerateOutFilesFromRequest(req, issuer)
		return
	}

	if cert.NotAfter.After(time.Now()) {
		logger.Printf("Expired certificate %s", req.OutCertPath, err)
		GenerateOutFilesFromRequest(req, issuer)
		return
	}
}

func GenerateOutFilesFromRequest(req CertificateRequest, issuer *Issuer) {
	logger.Printf("Generate key %s", req.OutKeyPath)
	publicKey, err := GeneratePrivateKey(req)
	if err != nil {
		logError(err)
		return
	}

	logger.Printf("Generate certificate %s", req.OutCertPath)
	if err := GenerateCertificate(req, publicKey, issuer); err != nil {
		logError(err)
		return
	}

	logger.Printf("Copy CA to %s", req.OutCAPath)
	if err := CopyCA(issuer, req.OutCAPath); err != nil {
		logError(err)
		return
	}
}

func logError(err error) {
	logger.Errorf("Failure: %v", err)
}
