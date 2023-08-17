package tls

import (
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/goten4/ucerts/internal/config"
)

func TestLoadCertificateRequest(t *testing.T) {
	viper.Reset()
	expected := CertificateRequest{
		OutCertPath:         "testdata/tls/server.crt",
		OutKeyPath:          "testdata/tls/key.pem",
		OutCAPath:           "testdata/tls/ca.pem",
		CommonName:          "test",
		Countries:           []string{"FR", "BE"},
		Organizations:       []string{"uCerts"},
		OrganizationalUnits: []string{"test"},
		Localities:          []string{"Bordeaux", "Bruxelles"},
		Provinces:           []string{"France", "Belgium"},
		StreetAddresses:     []string{"test street"},
		PostalCodes:         []string{"12345"},
		Duration:            12345 * time.Hour,
		RenewBefore:         123 * time.Hour,
		ExtKeyUsages:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:            []string{"localhost"},
		IPAddresses:         []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 1, 1)},
		PrivateKey:          PrivateKey{Algorithm: "ecdsa", Size: 384},
		IssuerPath:          IssuerPath{PublicKey: "testdata/ca.pem", PrivateKey: "testdata/ca-key.pem"},
	}

	actual, err := LoadCertificateRequest("testdata/valid.yaml")

	require.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestLoadCertificateRequest_WithDefaultValues(t *testing.T) {
	viper.Reset()
	config.DefaultCountries = []string{"DEF"}
	config.DefaultOrganizations = []string{"default O"}
	config.DefaultOrganizationalUnits = []string{"default OU"}
	config.DefaultLocalities = []string{"default L"}
	config.DefaultProvinces = []string{"default P"}
	config.DefaultStreetAddresses = []string{"default SA"}
	config.DefaultPostalCodes = []string{"3220"}
	expected := CertificateRequest{
		OutCertPath:         "testdata/tls/tls.crt",
		OutKeyPath:          "testdata/tls/tls.key",
		OutCAPath:           "testdata/tls/ca.crt",
		CommonName:          "test",
		Countries:           []string{"DEF"},
		Organizations:       []string{"default O"},
		OrganizationalUnits: []string{"default OU"},
		Localities:          []string{"default L"},
		Provinces:           []string{"default P"},
		StreetAddresses:     []string{"default SA"},
		PostalCodes:         []string{"3220"},
		Duration:            12345 * time.Hour,
		RenewBefore:         123 * time.Hour,
		ExtKeyUsages:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IssuerPath:          IssuerPath{PublicKey: "testdata/ca.crt", PrivateKey: "testdata/ca.key"},
	}

	actual, err := LoadCertificateRequest("testdata/valid-defaults.yaml")

	require.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestLoadCertificateRequest_WithErrors(t *testing.T) {
	for name, tt := range map[string]struct {
		certificateRequestFile string
		expectedError          error
	}{
		"Unknown file": {
			certificateRequestFile: "unknown",
			expectedError:          ErrOpenCertificateRequestFile,
		},
		"Missing out.dir": {
			certificateRequestFile: "testdata/missing-outdir.yaml",
			expectedError:          ErrMissingMandatoryField,
		},
		"Invalid extension": {
			certificateRequestFile: "testdata/invalid.ext",
			expectedError:          config.ErrInvalidExtension,
		},
		"Invalid file": {
			certificateRequestFile: "testdata/invalid.yaml",
			expectedError:          ErrReadCertificateRequestFile,
		},
		"Invalid key usages": {
			certificateRequestFile: "testdata/invalid-keyusage.yaml",
			expectedError:          ErrInvalidKeyUsages,
		},
		"Missing key usage": {
			certificateRequestFile: "testdata/missing-keyusages.yaml",
			expectedError:          ErrMissingMandatoryField,
		},
		"Invalid IP address": {
			certificateRequestFile: "testdata/invalid-ipaddresses.yaml",
			expectedError:          ErrInvalidIPAddress,
		},
	} {
		tc := tt // Use local variable to avoid closure-caused race condition
		t.Run(name, func(t *testing.T) {
			viper.Reset()

			_, err := LoadCertificateRequest(tc.certificateRequestFile)

			assert.ErrorIs(t, err, tc.expectedError)
		})
	}
}
