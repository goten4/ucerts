package tls

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/goten4/ucerts/internal/format"
)

var (
	ErrCreateFile = errors.New("create file")
	ErrWriteFile  = errors.New("write file")
	ErrReadDir    = errors.New("read directory")
)

func WritePemToFile(b *pem.Block, file string) error {
	pemFile, err := os.Create(file)
	if err != nil {
		return fmt.Errorf(format.WrapErrors, ErrCreateFile, err)
	}
	defer func() { _ = pemFile.Close() }()
	err = pem.Encode(pemFile, b)
	if err != nil {
		return fmt.Errorf(format.WrapErrors, ErrWriteFile, err)
	}
	return nil
}

func LoadCertFromFile(file string) (*x509.Certificate, error) {
	b, err := os.ReadFile(file)
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

func ReadDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf(format.WrapErrors, ErrReadDir, err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		info, _ := entry.Info()
		if !info.IsDir() {
			files = append(files, filepath.Join(dir, info.Name()))
		}
	}
	return files, nil
}

func MakeParentsDirectories(path string) bool {
	dir := filepath.Dir(path)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return false
		}
	}
	return true
}

func FileDoesNotExists(file string) bool {
	_, err := os.Stat(file)
	return errors.Is(err, os.ErrNotExist)
}
