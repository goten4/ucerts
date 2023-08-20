package tls

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestLoadCertificateRequests(t *testing.T) {
	var handledFiles []string
	mock(t, &HandleCertificateRequestFile, func(file string) { handledFiles = append(handledFiles, file) })

	LoadCertificateRequests("testdata/requests")

	assert.Equal(t, []string{"testdata/requests/test1.yaml", "testdata/requests/test2.yaml"}, handledFiles)
}

func TestHandleCertificateRequestFile_WithInvalidExtension(t *testing.T) {
	out := loggerOutput()

	HandleCertificateRequestFile("file.invalid")

	assert.Empty(t, out.String())
}

func TestHandleCertificateRequestFile_WithLoadCertificateRequestError(t *testing.T) {
	out := loggerOutput()
	mock(t, &LoadCertificateRequest, func(_ string) (CertificateRequest, error) {
		return CertificateRequest{}, errors.New("LoadCertificateRequest error")
	})

	HandleCertificateRequestFile("valid.yaml")

	expectedLogs := []string{
		`level=info msg="Handle certificate request valid.yaml"`,
		`level=error msg="Failed to load certificate request: LoadCertificateRequest error"`,
	}
	assert.Equal(t, expectedLogs, splitLogLines(out))
}

func TestHandleCertificateRequestFile_WithLoadIssuerError(t *testing.T) {
	out := loggerOutput()
	mock(t, &LoadCertificateRequest, func(_ string) (CertificateRequest, error) { return CertificateRequest{}, nil })
	mock(t, &LoadIssuer, func(_ IssuerPath) (*Issuer, error) { return nil, errors.New("LoadIssuer error") })

	HandleCertificateRequestFile("valid.yaml")

	expectedLogs := []string{
		`level=info msg="Handle certificate request valid.yaml"`,
		`level=error msg="Invalid issuer: LoadIssuer error"`,
	}
	assert.Equal(t, expectedLogs, splitLogLines(out))
}

func TestHandleCertificateRequestFile_WithLoadCertFromFileError(t *testing.T) {
	out := loggerOutput()
	mock(t, &LoadCertificateRequest, func(_ string) (CertificateRequest, error) { return CertificateRequest{OutCertPath: "tls.crt"}, nil })
	mock(t, &LoadIssuer, func(_ IssuerPath) (*Issuer, error) { return nil, nil })
	mock(t, &FileDoesNotExists, func(file string) bool { return false })
	mock(t, &LoadCertFromFile, func(_ string) (*x509.Certificate, error) { return nil, errors.New("LoadCertFromFile error") })
	mock(t, &GenerateOutFilesFromRequest, func(_ CertificateRequest, _ *Issuer) {})

	HandleCertificateRequestFile("valid.yaml")

	expectedLogs := []string{
		`level=info msg="Handle certificate request valid.yaml"`,
		`level=error msg="Invalid certificate tls.crt: LoadCertFromFile error"`,
	}
	assert.Equal(t, expectedLogs, splitLogLines(out))
}

func TestGenerateOutFilesFromRequest(t *testing.T) {
	out := loggerOutput()
	req := CertificateRequest{OutCAPath: "ca.crt", OutCertPath: "tls.crt", OutKeyPath: "tls.key"}
	mock(t, &GeneratePrivateKey, func(_ CertificateRequest) (crypto.PrivateKey, error) { return nil, nil })
	mock(t, &GenerateCertificate, func(_ CertificateRequest, _ crypto.PrivateKey, _ *Issuer) error { return nil })
	mock(t, &CopyCA, func(_ *Issuer, _ string) error { return nil })

	GenerateOutFilesFromRequest(req, &Issuer{PublicKey: &x509.Certificate{}})

	actualLogs := splitLogLines(out)
	expectedLogs := []string{
		`level=info msg="Generate key to tls.key"`,
		`level=info msg="Generate certificate to tls.crt"`,
		`level=info msg="Copy CA to ca.crt"`,
	}
	assert.Equal(t, expectedLogs, actualLogs)
}

func TestGenerateOutFilesFromRequest_WithoutIssuer(t *testing.T) {
	out := loggerOutput()
	req := CertificateRequest{OutCAPath: "ca.crt", OutCertPath: "tls.crt", OutKeyPath: "tls.key"}
	mock(t, &GeneratePrivateKey, func(_ CertificateRequest) (crypto.PrivateKey, error) { return nil, nil })
	mock(t, &GenerateCertificate, func(_ CertificateRequest, _ crypto.PrivateKey, _ *Issuer) error { return nil })

	GenerateOutFilesFromRequest(req, nil)

	actualLogs := splitLogLines(out)
	expectedLogs := []string{
		`level=info msg="Generate key to tls.key"`,
		`level=info msg="Generate certificate to tls.crt"`,
	}
	assert.Equal(t, expectedLogs, actualLogs)
}

func TestGenerateOutFilesFromRequest_WithError(t *testing.T) {
	req := CertificateRequest{OutCAPath: "ca.crt", OutCertPath: "tls.crt", OutKeyPath: "tls.key"}

	for name, tt := range map[string]struct {
		generatePrivateKey  func(_ CertificateRequest) (crypto.PrivateKey, error)
		generateCertificate func(_ CertificateRequest, _ crypto.PrivateKey, _ *Issuer) error
		copyCA              func(_ *Issuer, _ string) error
		expectedLogs        []string
	}{
		"GeneratePrivateKey error": {
			generatePrivateKey: func(_ CertificateRequest) (crypto.PrivateKey, error) {
				return nil, errors.New("GeneratePrivateKey error")
			},
			expectedLogs: []string{
				`level=info msg="Generate key to tls.key"`,
				`level=error msg="Failure: GeneratePrivateKey error"`,
			},
		},
		"GenerateCertificate error": {
			generatePrivateKey: func(_ CertificateRequest) (crypto.PrivateKey, error) { return nil, nil },
			generateCertificate: func(_ CertificateRequest, _ crypto.PrivateKey, _ *Issuer) error {
				return errors.New("GenerateCertificate error")
			},
			expectedLogs: []string{
				`level=info msg="Generate key to tls.key"`,
				`level=info msg="Generate certificate to tls.crt"`,
				`level=error msg="Failure: GenerateCertificate error"`,
			},
		},
		"CopyCA error": {
			generatePrivateKey:  func(_ CertificateRequest) (crypto.PrivateKey, error) { return nil, nil },
			generateCertificate: func(_ CertificateRequest, _ crypto.PrivateKey, _ *Issuer) error { return nil },
			copyCA:              func(_ *Issuer, _ string) error { return errors.New("CopyCA error") },
			expectedLogs: []string{
				`level=info msg="Generate key to tls.key"`,
				`level=info msg="Generate certificate to tls.crt"`,
				`level=info msg="Copy CA to ca.crt"`,
				`level=error msg="Failure: CopyCA error"`,
			},
		},
	} {
		tc := tt // Use local variable to avoid closure-caused race condition
		t.Run(name, func(t *testing.T) {
			out := loggerOutput()
			mock(t, &GeneratePrivateKey, tc.generatePrivateKey)
			mock(t, &GenerateCertificate, tc.generateCertificate)
			mock(t, &CopyCA, tc.copyCA)

			GenerateOutFilesFromRequest(req, &Issuer{PublicKey: &x509.Certificate{}})

			assert.Equal(t, tc.expectedLogs, splitLogLines(out))
		})
	}
}

func loggerOutput() *bytes.Buffer {
	var out bytes.Buffer
	logrus.SetOutput(&out)
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	return &out
}

func splitLogLines(out *bytes.Buffer) []string {
	return strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
}
