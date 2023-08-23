package config

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	KeyShutdownTimeout            = "shutdownTimeout"
	KeyInterval                   = "interval"
	KeyLogLevel                   = "log.level"
	KeyLogFormat                  = "log.format"
	KeyLogTimestampEnable         = "log.timestamp.enable"
	KeyLogTimestampFormat         = "log.timestamp.format"
	KeyCertificateRequestsPaths   = "certificateRequests.paths"
	KeyDefaultCountries           = "default.countries"
	KeyDefaultOrganizations       = "default.organizations"
	KeyDefaultOrganizationalUnits = "default.organizationalUnits"
	KeyDefaultLocalities          = "default.localities"
	KeyDefaultProvinces           = "default.provinces"
	KeyDefaultStreetAddresses     = "default.streetAddresses"
	KeyDefaultPostalCodes         = "default.postalCodes"
	KeyAgentListenGRPC            = "agent.grpc.listen"
	KeyKeepAlivePolicyMinTime     = "agent.grpc.keep_alive.policy_min_time"
	KeyKeepAliveTime              = "agent.grpc.keep_alive.time"
	KeyKeepAliveTimeout           = "agent.grpc.keep_alive.timeout"
)

type ServerGRPC struct {
	Listen                 string
	KeepAlivePolicyMinTime time.Duration
	KeepAliveTime          time.Duration
	KeepAliveTimeout       time.Duration
	TLSEnable              bool
	MTLSEnable             bool
	TLSCAPath              string
	TLSCertPath            string
	TLSKeyPath             string
}

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
	AgentGRPC                  ServerGRPC

	ErrInvalidExtension = errors.New("invalid extension")
)

func Init() {
	viper.SetDefault(KeyShutdownTimeout, 10*time.Second)
	viper.SetDefault(KeyInterval, 5*time.Minute)
	viper.SetDefault(KeyLogLevel, "info")
	viper.SetDefault(KeyLogFormat, "text")
	viper.SetDefault(KeyLogTimestampEnable, false)
	viper.SetDefault(KeyLogTimestampFormat, time.DateTime)
	viper.SetDefault(KeyAgentListenGRPC, ":4293")

	viper.SetEnvPrefix("UCERTS")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	configFile := viper.GetString("config")
	if configFile != "" {
		file, err := os.Open(configFile)
		if err != nil {
			logrus.Fatalf("Failed to load configuration file %s: %v", configFile, err)
		}
		ext, err := GetExtension(configFile)
		if err != nil {
			logrus.Fatalf("Failed to load configuration file %s: %v", configFile, err)
		}
		viper.SetConfigType(ext)
		if err := viper.ReadConfig(file); err != nil {
			logrus.Fatalf("Failed to read configuration file %s: %v", configFile, err)
		}
	}

	logLevel, err := logrus.ParseLevel(viper.GetString(KeyLogLevel))
	if err != nil {
		logrus.Fatalf("Invalid log level: %v", err)
	}
	logrus.SetLevel(logLevel)

	enableTimestamp := viper.GetBool(KeyLogTimestampEnable)
	timestampFormat := viper.GetString(KeyLogTimestampFormat)
	var formatter logrus.Formatter
	switch viper.GetString(KeyLogFormat) {
	case "json":
		formatter = &logrus.JSONFormatter{DisableTimestamp: !enableTimestamp, TimestampFormat: timestampFormat}
	default:
		formatter = &logrus.TextFormatter{DisableTimestamp: !enableTimestamp, FullTimestamp: true, TimestampFormat: timestampFormat}
	}
	logrus.SetFormatter(formatter)

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
	AgentGRPC = ServerGRPC{
		Listen: viper.GetString(KeyAgentListenGRPC),
	}

	logrus.Infof("Configuration file loaded: %s", configFile)
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
