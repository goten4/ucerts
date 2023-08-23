package manager

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/goten4/ucerts/internal/config"
)

var LoadCertificateRequests = func() {
	for _, dir := range config.CertificateRequestsPaths {
		files, err := ReadDir(dir)
		if err != nil {
			logrus.Errorf("Failed to read directory %s: %v", dir, err)
			return
		}
		for _, file := range files {
			HandleCertificateRequestFile(file)
		}
	}
}

var HandleCertificateRequestFile = func(file string) {
	// Handle only files with compatible extension
	if _, err := config.GetExtension(file); err != nil {
		return
	}

	logrus.Infof("Handle certificate request %s", file)
	req, err := LoadCertificateRequest(file)
	if err != nil {
		logrus.Errorf("Failed to load certificate request: %v", err)
		return
	}

	issuer, err := LoadIssuer(req.IssuerPath)
	if err != nil {
		logrus.Errorf("Invalid issuer: %v", err)
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
		logrus.Errorf("Invalid certificate %s: %v", req.OutCertPath, err)
		GenerateOutFilesFromRequest(req, issuer)
		return
	}

	if cert.NotAfter.Before(time.Now().Add(req.RenewBefore)) {
		logrus.Infof("Expired certificate %s", req.OutCertPath)
		GenerateOutFilesFromRequest(req, issuer)
		return
	}
}

var GenerateOutFilesFromRequest = func(req CertificateRequest, issuer *Issuer) {
	logrus.Infof("Generate key to %s", req.OutKeyPath)
	key, err := GeneratePrivateKey(req)
	if err != nil {
		logError(err)
		return
	}

	logrus.Infof("Generate certificate to %s", req.OutCertPath)
	if err := GenerateCertificate(req, key, issuer); err != nil {
		logError(err)
		return
	}

	if issuer != nil {
		logrus.Infof("Copy CA to %s", req.OutCAPath)
		if err := CopyCA(issuer, req.OutCAPath); err != nil {
			logError(err)
			return
		}
	}
}

func logError(err error) {
	logrus.Errorf("Failure: %v", err)
}
