package config

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/goten4/ucerts/internal/logger"
)

const (
	KeyShutdownTimeout            = "shutdown.timeout"
	KeyInterval                   = "interval"
	KeyCertificateRequestsPaths   = "certificateRequests.paths"
	KeyDefaultCountries           = "default.countries"
	KeyDefaultOrganizations       = "default.organizations"
	KeyDefaultOrganizationalUnits = "default.organizationalUnits"
	KeyDefaultLocalities          = "default.localities"
	KeyDefaultProvinces           = "default.provinces"
	KeyDefaultStreetAddresses     = "default.streetAddresses"
	KeyDefaultPostalCodes         = "default.postalCodes"
)

var (
	ShutdownTimeout            time.Duration
	Interval                   time.Duration
	CertificateRequestsPaths   []string
	DefaultCountries           []string
	DefaultOrganizations       []string
	DefaultOrganizationalUnits []string
	DefaultLocalities          []string
	DefaultProvinces           []string
	DefaultStreetAddresses     []string
	DefaultPostalCodes         []string

	ErrInvalidExtension = errors.New("invalid extension")
)

func Init() {
	viper.SetDefault(KeyShutdownTimeout, 10*time.Second)
	viper.SetDefault(KeyInterval, 5*time.Minute)

	viper.SetEnvPrefix("UCERTS")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if configFile := viper.GetString("config"); configFile != "" {
		logger.Printf("Loading configuration file %s", configFile)
		file, err := os.Open(configFile)
		if err != nil {
			logger.Failf("Failed to load configuration file: %v", configFile, err)
		}
		ext, err := GetExtension(configFile)
		if err != nil {
			logger.Failf("Failed to load configuration file: %v", configFile, err)
		}
		viper.SetConfigType(ext)
		if err := viper.ReadConfig(file); err != nil {
			logger.Failf("Failed to read configuration file: %v", configFile, err)
		}
	}

	ShutdownTimeout = viper.GetDuration(KeyShutdownTimeout)
	Interval = viper.GetDuration(KeyInterval)
	CertificateRequestsPaths = viper.GetStringSlice(KeyCertificateRequestsPaths)
	DefaultCountries = viper.GetStringSlice(KeyDefaultCountries)
	DefaultOrganizations = viper.GetStringSlice(KeyDefaultOrganizations)
	DefaultOrganizationalUnits = viper.GetStringSlice(KeyDefaultOrganizationalUnits)
	DefaultLocalities = viper.GetStringSlice(KeyDefaultLocalities)
	DefaultProvinces = viper.GetStringSlice(KeyDefaultProvinces)
	DefaultStreetAddresses = viper.GetStringSlice(KeyDefaultStreetAddresses)
	DefaultPostalCodes = viper.GetStringSlice(KeyDefaultPostalCodes)
}

func GetExtension(configFile string) (string, error) {
	ext := filepath.Ext(configFile)
	if len(ext) == 0 {
		return "", ErrInvalidExtension
	}
	ext = ext[1:]
	if slices.Contains(viper.SupportedExts, ext) {
		return ext, nil
	}
	return "", ErrInvalidExtension
}
