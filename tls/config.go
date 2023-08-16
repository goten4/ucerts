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
	KeyOutDir             = "out.dir"
	KeyOutCert            = "out.cert"
	KeyOutKey             = "out.key"
	KeyOutCA              = "out.ca"
	KeyCommonName         = "commonName"
	KeyDuration           = "duration"
	KeyRenewBefore        = "renewBefore"
	KeyExtKeyUsage        = "extKeyUsage"
	KeyDNSNames           = "dnsNames"
	KeyIPAddresses        = "ipAddresses"
	KeyCountry            = "country"
	KeyOrganization       = "organization"
	KeyOrganizationalUnit = "organizationalUnit"
	KeyLocality           = "locality"
	KeyProvince           = "province"
	KeyStreetAddress      = "streetAddress"
	KeyPostalCode         = "postalCode"
)

var (
	ErrOpenConfigFile        = errors.New("open file")
	ErrReadConfigFile        = errors.New("read file")
	ErrInvalidKeyUsage       = errors.New("invalid key usage")
	ErrInvalidIPAddress      = errors.New("invalid ip address")
	ErrMissingMandatoryField = errors.New("missing mandatory field")
)

type Config struct {
	OutCertPath        string
	OutKeyPath         string
	OutCAPath          string
	CommonName         string
	Country            []string
	Organization       []string
	OrganizationalUnit []string
	Locality           []string
	Province           []string
	StreetAddress      []string
	PostalCode         []string
	Duration           time.Duration
	RenewBefore        time.Duration
	ExtKeyUsage        []x509.ExtKeyUsage
	DNSNames           []string
	IPAddresses        []net.IP
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
	conf.SetDefault(KeyCountry, config.DefaultCountry)
	conf.SetDefault(KeyOrganization, config.DefaultOrganization)
	conf.SetDefault(KeyOrganizationalUnit, config.DefaultOrganizationalUnit)
	conf.SetDefault(KeyLocality, config.DefaultLocality)
	conf.SetDefault(KeyProvince, config.DefaultProvince)
	conf.SetDefault(KeyStreetAddress, config.DefaultStreetAddress)
	conf.SetDefault(KeyPostalCode, config.DefaultPostalCode)

	outDir := conf.GetString(KeyOutDir)
	if outDir == "" {
		return Config{}, fmt.Errorf("%w: %s", ErrMissingMandatoryField, KeyOutDir)
	}

	tlsConf := Config{
		OutCertPath:        filepath.Join(outDir, conf.GetString(KeyOutCert)),
		OutKeyPath:         filepath.Join(outDir, conf.GetString(KeyOutKey)),
		OutCAPath:          filepath.Join(outDir, conf.GetString(KeyOutCA)),
		CommonName:         conf.GetString(KeyCommonName),
		Country:            conf.GetStringSlice(KeyCountry),
		Organization:       conf.GetStringSlice(KeyOrganization),
		OrganizationalUnit: conf.GetStringSlice(KeyOrganizationalUnit),
		Locality:           conf.GetStringSlice(KeyLocality),
		Province:           conf.GetStringSlice(KeyProvince),
		StreetAddress:      conf.GetStringSlice(KeyStreetAddress),
		PostalCode:         conf.GetStringSlice(KeyPostalCode),
		Duration:           conf.GetDuration(KeyDuration),
		RenewBefore:        conf.GetDuration(KeyRenewBefore),
	}

	for _, s := range conf.GetStringSlice(KeyExtKeyUsage) {
		extKeyUsage, err := findExtKeyUsage(s)
		if err != nil {
			return Config{}, fmt.Errorf(format.WrapErrorString, ErrInvalidKeyUsage, s)
		}
		tlsConf.ExtKeyUsage = append(tlsConf.ExtKeyUsage, extKeyUsage)
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
	return 0, ErrInvalidKeyUsage
}
