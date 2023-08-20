package config

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInit(t *testing.T) {
	viper.Reset()
	var out bytes.Buffer
	logrus.SetOutput(&out)
	err := os.Setenv("UCERTS_CONFIG", "testdata/valid.yaml")
	require.NoError(t, err)

	Init()

	assert.Equal(t, 123*time.Second, ShutdownTimeout)
	assert.Equal(t, 321*time.Second, Interval)
	assert.Equal(t, logrus.DebugLevel, logrus.GetLevel())
	assert.Equal(t, []string{"test"}, CertificateRequestsPaths)
	assert.Equal(t, []string{"testC"}, DefaultCountries)
	assert.Equal(t, []string{"testO"}, DefaultOrganizations)
	assert.Equal(t, []string{"testOU"}, DefaultOrganizationalUnits)
	assert.Equal(t, []string{"testL"}, DefaultLocalities)
	assert.Equal(t, []string{"testP"}, DefaultProvinces)
	assert.Equal(t, []string{"testSA"}, DefaultStreetAddresses)
	assert.Equal(t, []string{"testPC"}, DefaultPostalCodes)
	var line map[string]string
	err = json.Unmarshal(out.Bytes(), &line)
	require.NoError(t, err)
	assert.Equal(t, "Configuration file loaded: testdata/valid.yaml", line["msg"])
	assert.Equal(t, "info", line["level"])
	_, err = time.Parse("2006-01-02T15:04:05", line["time"])
	assert.NoError(t, err)
}

func TestInit_WithDefaultValues(t *testing.T) {
	err := os.Unsetenv("UCERTS_CONFIG")
	require.NoError(t, err)
	viper.Reset()
	var out bytes.Buffer
	logrus.SetOutput(&out)

	Init()

	assert.Equal(t, 10*time.Second, ShutdownTimeout)
	assert.Equal(t, 5*time.Minute, Interval)
	assert.Equal(t, logrus.InfoLevel, logrus.GetLevel())
	assert.Empty(t, CertificateRequestsPaths)
	assert.Empty(t, DefaultCountries)
	assert.Empty(t, DefaultOrganizations)
	assert.Empty(t, DefaultOrganizationalUnits)
	assert.Empty(t, DefaultLocalities)
	assert.Empty(t, DefaultProvinces)
	assert.Empty(t, DefaultStreetAddresses)
	assert.Empty(t, DefaultPostalCodes)
	assert.Equal(t, "level=info msg=\"Configuration file loaded: \"\n", out.String())
}

func TestGetExtension(t *testing.T) {
	for name, tt := range map[string]struct {
		file     string
		expected string
	}{
		"json":       {file: "test.json", expected: "json"},
		"toml":       {file: "test.toml", expected: "toml"},
		"yaml":       {file: "test.yaml", expected: "yaml"},
		"yml":        {file: "test.yml", expected: "yml"},
		"properties": {file: "test.properties", expected: "properties"},
		"props":      {file: "test.props", expected: "props"},
		"prop":       {file: "test.prop", expected: "prop"},
		"hcl":        {file: "test.hcl", expected: "hcl"},
		"tfvars":     {file: "test.tfvars", expected: "tfvars"},
		"dotenv":     {file: "test.dotenv", expected: "dotenv"},
		"env":        {file: "test.env", expected: "env"},
		"ini":        {file: "test.ini", expected: "ini"},
	} {
		tc := tt // Use local variable to avoid closure-caused race condition
		t.Run(name, func(t *testing.T) {
			actual, err := GetExtension(tc.file)

			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestGetExtension_WithError(t *testing.T) {
	for name, tt := range map[string]struct {
		file          string
		expectedError error
	}{
		"Invalid extension": {file: "test.invalid", expectedError: ErrInvalidExtension},
		"Missing extension": {file: "test", expectedError: ErrInvalidExtension},
	} {
		tc := tt // Use local variable to avoid closure-caused race condition
		t.Run(name, func(t *testing.T) {
			_, err := GetExtension(tc.file)

			assert.ErrorIs(t, ErrInvalidExtension, err)
		})
	}
}
