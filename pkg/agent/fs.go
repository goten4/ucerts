package agent

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/goten4/ucerts/internal/format"
)

var (
	ErrCreateFile       = errors.New("create file")
	ErrReadFile         = errors.New("read file")
	ErrParseCertificate = errors.New("parse certificate")
	ErrEncode           = errors.New("encode")
	ErrInvalidPEMBlock  = errors.New("invalid PEM block")
)

var WritePemToFile = func(b []byte, file string) error {

	// No need to overwrite file if contents are equals
	if contentsAreEquals(b, file) {
		return nil
	}

	pemBlock, _ := pem.Decode(b)
	if pemBlock == nil {
		return ErrInvalidPEMBlock
	}

	pemFile, err := os.Create(file)
	if err != nil {
		return fmt.Errorf(format.WrapErrors, ErrCreateFile, err)
	}
	defer func() { _ = pemFile.Close() }()

	err = pem.Encode(pemFile, pemBlock)
	if err != nil {
		return fmt.Errorf(format.WrapErrors, ErrEncode, err)
	}
	return nil
}

func contentsAreEquals(data []byte, file string) bool {
	fileContent, err := os.ReadFile(file)
	if err != nil {
		// if we cannot read file content, let's consider that contents are not equals
		return false
	}
	return sha1sum(data) == sha1sum(fileContent)
}

func sha1sum(data []byte) string {
	hash := sha1.New()
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

var LoadCertFromFile = func(file string) (*x509.Certificate, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf(format.WrapErrors, ErrReadFile, err)
	}

	certPEMBlock, _ := pem.Decode(b)
	if certPEMBlock == nil || certPEMBlock.Type != "CERTIFICATE" {
		return nil, ErrInvalidPEMBlock
	}

	x509Cert, err := x509.ParseCertificate(certPEMBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf(format.WrapErrors, ErrParseCertificate, err)
	}

	return x509Cert, nil
}

var MakeParentsDirectories = func(path string) bool {
	dir := filepath.Dir(path)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return false
		}
	}
	return true
}
