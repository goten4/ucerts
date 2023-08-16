package tls

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/goten4/ucerts/internal/config"
	"github.com/goten4/ucerts/internal/format"
)

const (
	KeyOutDir              = "out.dir"
	KeyOutCert             = "out.cert"
	KeyOutKey              = "out.key"
	KeyOutCA               = "out.ca"
	KeyCommonName          = "commonName"
	KeySerialNumber        = "serialNumber"
	KeyDuration            = "duration"
	KeyRenewBefore         = "renewBefore"
	KeyExtKeyUsages        = "extKeyUsages"
	KeyDNSNames            = "dnsNames"
	KeyIPAddresses         = "ipAddresses"
	KeyCountries           = "subject.countries"
	KeyOrganizations       = "subject.organizations"
	KeyOrganizationalUnits = "subject.organizationalUnits"
	KeyLocalities          = "subject.localities"
	KeyProvinces           = "subject.provinces"
	KeyStreetAddresses     = "subject.streetAddresses"
	KeyPostalCodes         = "subject.postalCodes"
)

var (
	ErrOpenConfigFile        = errors.New("open file")
	ErrReadConfigFile        = errors.New("read file")
	ErrInvalidKeyUsages      = errors.New("invalid key usages")
	ErrInvalidIPAddress      = errors.New("invalid ip addresses")
	ErrMissingMandatoryField = errors.New("missing mandatory field")
)

type Config struct {
	OutCertPath         string
	OutKeyPath          string
	OutCAPath           string
	CommonName          string
	Countries           []string
	Organizations       []string
	OrganizationalUnits []string
	Localities          []string
	Provinces           []string
	StreetAddresses     []string
	PostalCodes         []string
	Duration            time.Duration
	RenewBefore         time.Duration
	ExtKeyUsages        []x509.ExtKeyUsage
	DNSNames            []string
	IPAddresses         []net.IP
}

func LoadConfig(path string) (Config, error) {
	conf := viper.New()
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf(format.WrapErrors, ErrOpenConfigFile, err)
	}
	ext, err := config.GetExtension(path)
	if err != nil {
		return Config{}, err
	}
	conf.SetConfigType(ext)
	if err := conf.ReadConfig(file); err != nil {
		return Config{}, fmt.Errorf(format.WrapErrors, ErrReadConfigFile, err)
	}

	conf.SetDefault(KeyOutCert, "tls.crt")
	conf.SetDefault(KeyOutKey, "tls.key")
	conf.SetDefault(KeyOutCA, "ca.crt")
	conf.SetDefault(KeyCountries, config.DefaultCountries)
	conf.SetDefault(KeyOrganizations, config.DefaultOrganizations)
	conf.SetDefault(KeyOrganizationalUnits, config.DefaultOrganizationalUnits)
	conf.SetDefault(KeyLocalities, config.DefaultLocalities)
	conf.SetDefault(KeyProvinces, config.DefaultProvinces)
	conf.SetDefault(KeyStreetAddresses, config.DefaultStreetAddresses)
	conf.SetDefault(KeyPostalCodes, config.DefaultPostalCodes)

	outDir := conf.GetString(KeyOutDir)
	if outDir == "" {
		return Config{}, fmt.Errorf(format.WrapErrorString, ErrMissingMandatoryField, KeyOutDir)
	}

	tlsConf := Config{
		OutCertPath:         filepath.Join(outDir, conf.GetString(KeyOutCert)),
		OutKeyPath:          filepath.Join(outDir, conf.GetString(KeyOutKey)),
		OutCAPath:           filepath.Join(outDir, conf.GetString(KeyOutCA)),
		CommonName:          conf.GetString(KeyCommonName),
		Countries:           conf.GetStringSlice(KeyCountries),
		Organizations:       conf.GetStringSlice(KeyOrganizations),
		OrganizationalUnits: conf.GetStringSlice(KeyOrganizationalUnits),
		Localities:          conf.GetStringSlice(KeyLocalities),
		Provinces:           conf.GetStringSlice(KeyProvinces),
		StreetAddresses:     conf.GetStringSlice(KeyStreetAddresses),
		PostalCodes:         conf.GetStringSlice(KeyPostalCodes),
		Duration:            conf.GetDuration(KeyDuration),
		RenewBefore:         conf.GetDuration(KeyRenewBefore),
	}

	for _, s := range conf.GetStringSlice(KeyExtKeyUsages) {
		extKeyUsage, err := findExtKeyUsage(s)
		if err != nil {
			return Config{}, fmt.Errorf(format.WrapErrorString, ErrInvalidKeyUsages, s)
		}
		tlsConf.ExtKeyUsages = append(tlsConf.ExtKeyUsages, extKeyUsage)
	}
	if len(tlsConf.ExtKeyUsages) == 0 {
		return Config{}, fmt.Errorf(format.WrapErrorString, ErrMissingMandatoryField, KeyExtKeyUsages)
	}

	for _, dnsName := range conf.GetStringSlice(KeyDNSNames) {
		tlsConf.DNSNames = append(tlsConf.DNSNames, dnsName)
	}

	for _, s := range conf.GetStringSlice(KeyIPAddresses) {
		ipAddr := net.ParseIP(s)
		if ipAddr == nil {
			return Config{}, fmt.Errorf(format.WrapErrorString, ErrInvalidIPAddress, s)
		}
		tlsConf.IPAddresses = append(tlsConf.IPAddresses, ipAddr)
	}

	return tlsConf, nil
}

func findExtKeyUsage(s string) (x509.ExtKeyUsage, error) {
	switch strings.ToLower(s) {
	case "any":
		return x509.ExtKeyUsageAny, nil
	case "server auth":
		return x509.ExtKeyUsageServerAuth, nil
	case "client auth":
		return x509.ExtKeyUsageClientAuth, nil
	case "CodeSigning":
		return x509.ExtKeyUsageCodeSigning, nil
	case "email protection":
		return x509.ExtKeyUsageEmailProtection, nil
	case "ipsec end system":
		return x509.ExtKeyUsageIPSECEndSystem, nil
	case "ipsec tunnel":
		return x509.ExtKeyUsageIPSECTunnel, nil
	case "ipsec user":
		return x509.ExtKeyUsageIPSECUser, nil
	case "time stamping":
		return x509.ExtKeyUsageTimeStamping, nil
	case "ocsp signing":
		return x509.ExtKeyUsageOCSPSigning, nil
	case "microsoft server gated crypto":
		return x509.ExtKeyUsageMicrosoftServerGatedCrypto, nil
	case "netscape server gated crypto":
		return x509.ExtKeyUsageNetscapeServerGatedCrypto, nil
	case "microsoft commercial code signing":
		return x509.ExtKeyUsageMicrosoftCommercialCodeSigning, nil
	case "microsoft kernel code signing":
		return x509.ExtKeyUsageMicrosoftKernelCodeSigning, nil
	}
	return 0, ErrInvalidKeyUsages
}
