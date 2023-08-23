package manager

import (
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWritePemToFile(t *testing.T) {
	pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x30, 0x2e, 0x2, 0x1, 0x0, 0x30, 0x5, 0x6, 0x3, 0x2b, 0x65, 0x70, 0x4, 0x22, 0x4, 0x20, 0x17, 0xe0, 0x78, 0x2b, 0x5d, 0x5c, 0x7d, 0xde, 0x3a, 0xb2, 0x4a, 0xc2, 0x6b, 0x8d, 0xd6, 0xd3, 0x2d, 0xa5, 0x72, 0x2b, 0xcd, 0xfe, 0x9e, 0xa1, 0xa1, 0x60, 0xb3, 0x77, 0xb, 0xcd, 0x2c, 0xc0}}
	expected := "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIBfgeCtdXH3eOrJKwmuN1tMtpXIrzf6eoaFgs3cLzSzA\n-----END PRIVATE KEY-----\n"

	err := WritePemToFile(pemBlock, "testdata/test-key.pem")

	require.NoError(t, err)
	actual, err := os.ReadFile("testdata/test-key.pem")
	require.NoError(t, err)
	assert.Equal(t, expected, string(actual))
}

func TestWritePemToFile_WithError(t *testing.T) {
	for name, tt := range map[string]struct {
		pemBlock      *pem.Block
		file          string
		expectedError error
	}{
		"Create file error": {
			pemBlock:      &pem.Block{},
			file:          "dir/unknown",
			expectedError: ErrCreateFile,
		},
		"Encode error": {
			pemBlock:      &pem.Block{Headers: map[string]string{"invalid:key": ""}},
			file:          "testdata/invalid.crt",
			expectedError: ErrEncode,
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

func TestReadDir(t *testing.T) {
	files, err := ReadDir("testdata/testdir")

	require.NoError(t, err)
	assert.Equal(t, []string{"testdata/testdir/file1.txt", "testdata/testdir/file2.txt"}, files)
}

func TestReadDir_WithError(t *testing.T) {
	_, err := ReadDir("testdata/unknown")

	assert.ErrorIs(t, err, ErrReadDir)
}

func TestMakeParentsDirectories(t *testing.T) {
	assert.True(t, MakeParentsDirectories("testdata/test.crt"))
}

func TestFileDoesNotExists(t *testing.T) {
	assert.True(t, FileDoesNotExists("unknown"))
	assert.False(t, FileDoesNotExists("testdata/test.crt"))
}
