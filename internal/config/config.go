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
	KeyShutdownTimeout           = "shutdown.timeout"
	KeyInterval                  = "interval"
	KeyTLSConfigPaths            = "tls.configPaths"
	KeyCAPath                    = "caPath"
	KeyCAKeyPath                 = "caKeyPath"
	KeyDefaultCountry            = "default.country"
	KeyDefaultOrganization       = "default.organization"
	KeyDefaultOrganizationalUnit = "default.organizationalUnit"
	KeyDefaultLocality           = "default.locality"
	KeyDefaultProvince           = "default.province"
	KeyDefaultStreetAddress      = "default.streetAddress"
	KeyDefaultPostalCode         = "default.postalCode"
)

var (
	ShutdownTimeout           time.Duration
	Interval                  time.Duration
	TLSConfigPaths            []string
	CAPath                    string
	CAKeyPath                 string
	DefaultCountry            string
	DefaultOrganization       string
	DefaultOrganizationalUnit string
	DefaultLocality           string
	DefaultProvince           string
	DefaultStreetAddress      string
	DefaultPostalCode         string

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
	TLSConfigPaths = viper.GetStringSlice(KeyTLSConfigPaths)
	CAPath = viper.GetString(KeyCAPath)
	CAKeyPath = viper.GetString(KeyCAKeyPath)
	DefaultCountry = viper.GetString(KeyDefaultCountry)
	DefaultOrganization = viper.GetString(KeyDefaultOrganization)
	DefaultOrganizationalUnit = viper.GetString(KeyDefaultOrganizationalUnit)
	DefaultLocality = viper.GetString(KeyDefaultLocality)
	DefaultProvince = viper.GetString(KeyDefaultProvince)
	DefaultStreetAddress = viper.GetString(KeyDefaultStreetAddress)
	DefaultPostalCode = viper.GetString(KeyDefaultPostalCode)

	const errMissingFormat = "Error in configuration: %s must be set"
	if len(TLSConfigPaths) == 0 {
		logger.Failf(errMissingFormat, KeyTLSConfigPaths)
	}
	if CAPath == "" {
		logger.Failf(errMissingFormat, KeyCAPath)
	}
	if CAKeyPath == "" {
		logger.Failf(errMissingFormat, KeyCAKeyPath)
	}
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
