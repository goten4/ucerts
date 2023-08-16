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

func TestLoadConfig(t *testing.T) {
	viper.Reset()
	expected := Config{
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
	}

	actual, err := LoadConfig("testdata/valid.yaml")

	require.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestLoadConfig_WithDefaultValues(t *testing.T) {
	viper.Reset()
	config.DefaultCountries = []string{"DEF"}
	config.DefaultOrganizations = []string{"default O"}
	config.DefaultOrganizationalUnits = []string{"default OU"}
	config.DefaultLocalities = []string{"default L"}
	config.DefaultProvinces = []string{"default P"}
	config.DefaultStreetAddresses = []string{"default SA"}
	config.DefaultPostalCodes = []string{"3220"}
	expected := Config{
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
	}

	actual, err := LoadConfig("testdata/valid-defaults.yaml")

	require.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestLoadConfig_WithErrors(t *testing.T) {
	for name, tt := range map[string]struct {
		configFile    string
		expectedError error
	}{
		"Unknown file": {
			configFile:    "unknown",
			expectedError: ErrOpenConfigFile,
		},
		"Missing out.dir": {
			configFile:    "testdata/missing-outdir.yaml",
			expectedError: ErrMissingMandatoryField,
		},
		"Invalid extension": {
			configFile:    "testdata/invalid.ext",
			expectedError: config.ErrInvalidExtension,
		},
		"Invalid file": {
			configFile:    "testdata/invalid.yaml",
			expectedError: ErrReadConfigFile,
		},
		"Invalid key usages": {
			configFile:    "testdata/invalid-keyusages.yaml",
			expectedError: ErrInvalidKeyUsages,
		},
		"Missing key usage": {
			configFile:    "testdata/missing-keyusages.yaml",
			expectedError: ErrMissingMandatoryField,
		},
		"Invalid IP address": {
			configFile:    "testdata/invalid-ipaddresses.yaml",
			expectedError: ErrInvalidIPAddress,
		},
	} {
		tc := tt // Use local variable to avoid closure-caused race condition
		t.Run(name, func(t *testing.T) {
			viper.Reset()

			_, err := LoadConfig(tc.configFile)

			assert.ErrorIs(t, err, tc.expectedError)
		})
	}
}
