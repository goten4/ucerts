package agent

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWritePemToFile(t *testing.T) {
	expected := "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIBfgeCtdXH3eOrJKwmuN1tMtpXIrzf6eoaFgs3cLzSzA\n-----END PRIVATE KEY-----\n"
	pemBlock := []byte(expected)

	err := WritePemToFile(pemBlock, "testdata/test-key.pem")

	require.NoError(t, err)
	actual, err := os.ReadFile("testdata/test-key.pem")
	require.NoError(t, err)
	assert.Equal(t, expected, string(actual))
}

func TestWritePemToFile_WithError(t *testing.T) {
	for name, tt := range map[string]struct {
		pemBlock      []byte
		file          string
		expectedError error
	}{
		"Invalid PEM block": {
			pemBlock:      []byte("invalid block"),
			file:          "testdata/invalid.crt",
			expectedError: ErrInvalidPEMBlock,
		},
		"Create file error": {
			pemBlock:      []byte("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIBfgeCtdXH3eOrJKwmuN1tMtpXIrzf6eoaFgs3cLzSzA\n-----END PRIVATE KEY-----\n"),
			file:          "dir/unknown",
			expectedError: ErrCreateFile,
		},
	} {
		tc := tt // Use local variable to avoid closure-caused race condition
		t.Run(name, func(t *testing.T) {
			err := WritePemToFile(tc.pemBlock, tc.file)

			assert.ErrorIs(t, err, tc.expectedError)
		})
	}
}

func TestLoadCertFromFile(t *testing.T) {
	cert, err := LoadCertFromFile("testdata/test.crt")

	require.NoError(t, err)
	assert.Equal(t, "localhost", cert.Subject.CommonName)
}

func TestLoadCertFromFile_WithError(t *testing.T) {
	for name, tt := range map[string]struct {
		file          string
		expectedError error
	}{
		"Read file error": {
			file:          "dir/unknown",
			expectedError: ErrReadFile,
		},
		"Decode error": {
			file:          "testdata/invalid.crt",
			expectedError: ErrInvalidPEMBlock,
		},
		"Parse certificate error": {
			file:          "testdata/truncated.crt",
			expectedError: ErrParseCertificate,
		},
	} {
		tc := tt // Use local variable to avoid closure-caused race condition
		t.Run(name, func(t *testing.T) {
			_, err := LoadCertFromFile(tc.file)

			assert.ErrorIs(t, err, tc.expectedError)
		})
	}
}

func TestMakeParentsDirectories(t *testing.T) {
	assert.True(t, MakeParentsDirectories("testdata/test.crt"))
}
