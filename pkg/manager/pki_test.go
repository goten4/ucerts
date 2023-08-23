package manager

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePrivateKey(t *testing.T) {
	for name, tt := range map[string]struct {
		req          CertificateRequest
		expectedType string
	}{
		"Default is RSA": {
			req:          CertificateRequest{},
			expectedType: "RSA PRIVATE KEY",
		},
		"RSA": {
			req:          CertificateRequest{PrivateKey: PrivateKey{Algorithm: "rsa"}},
			expectedType: "RSA PRIVATE KEY",
		},
		"ECDSA": {
			req:          CertificateRequest{PrivateKey: PrivateKey{Algorithm: "ecdsa", Size: 256}},
			expectedType: "EC PRIVATE KEY",
		},
		"ECDSA default size is 256": {
			req:          CertificateRequest{PrivateKey: PrivateKey{Algorithm: "ecdsa"}},
			expectedType: "EC PRIVATE KEY",
		},
		"ED25519": {
			req:          CertificateRequest{PrivateKey: PrivateKey{Algorithm: "ed25519"}},
			expectedType: "PRIVATE KEY",
		},
	} {
		tc := tt // Use local variable to avoid closure-caused race condition
		t.Run(name, func(t *testing.T) {
			var pemBlock *pem.Block
			mock(t, &WritePemToFile, func(b *pem.Block, _ string) error {
				pemBlock = b
				return nil
			})

			_, err := GeneratePrivateKey(tc.req)

			require.NoError(t, err)
			assert.Equal(t, tc.expectedType, pemBlock.Type)
		})
	}
}

func TestGeneratePrivateKey_WithError(t *testing.T) {
	for name, tt := range map[string]struct {
		req            CertificateRequest
		writePemToFile func(_ *pem.Block, _ string) error
		expectedError  error
	}{
		"Unsupported algorithm": {
			req:            CertificateRequest{PrivateKey: PrivateKey{Algorithm: "invalid"}},
			writePemToFile: func(_ *pem.Block, _ string) error { return nil },
			expectedError:  ErrUnsupportedPrivateKeyAlgorithm,
		},
		"Write error": {
			req:            CertificateRequest{PrivateKey: PrivateKey{Algorithm: "RSA"}},
			writePemToFile: func(_ *pem.Block, _ string) error { return errors.New("error") },
			expectedError:  ErrGenerateKey,
		},
	} {
		tc := tt // Use local variable to avoid closure-caused race condition
		t.Run(name, func(t *testing.T) {
			mock(t, &WritePemToFile, tc.writePemToFile)

			_, err := GeneratePrivateKey(tc.req)

			assert.ErrorIs(t, err, tc.expectedError)
		})
	}
}

func TestGenerateCertificate(t *testing.T) {
	var req CertificateRequest
	var pemBlock *pem.Block
	mock(t, &WritePemToFile, func(b *pem.Block, _ string) error {
		pemBlock = b
		return nil
	})
	key, err := GeneratePrivateKey(req)
	require.NoError(t, err)

	err = GenerateCertificate(req, key, nil)

	require.NoError(t, err)
	assert.Equal(t, "CERTIFICATE", pemBlock.Type)
}

func TestGenerateCertificate_WithError(t *testing.T) {
	var req CertificateRequest
	mock(t, &WritePemToFile, func(_ *pem.Block, _ string) error { return nil })
	key, err := GeneratePrivateKey(req)
	require.NoError(t, err)
	mock(t, &WritePemToFile, func(_ *pem.Block, _ string) error { return errors.New("error") })

	err = GenerateCertificate(req, key, nil)

	require.ErrorIs(t, err, ErrGenerateCert)
}

func TestCopyCA(t *testing.T) {
	issuer, err := LoadIssuer(IssuerPath{PublicKey: "testdata/ca.crt", PrivateKey: "testdata/ca.key"})
	require.NoError(t, err)

	err = CopyCA(issuer, "testdata/test-ca.crt")

	require.NoError(t, err)
	expected, err := os.ReadFile("testdata/ca.crt")
	require.NoError(t, err)
	actual, err := os.ReadFile("testdata/test-ca.crt")
	require.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestCopyCA_WithError(t *testing.T) {
	mock(t, &WritePemToFile, func(_ *pem.Block, _ string) error { return errors.New("error") })

	err := CopyCA(&Issuer{PublicKey: &x509.Certificate{}}, "")

	require.ErrorIs(t, err, ErrCopyCA)
}
