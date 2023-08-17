package tls

import (
	"encoding/pem"
	"errors"
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
