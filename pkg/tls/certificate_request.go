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
	KeyIsCA                = "isCA"
	KeyDuration            = "duration"
	KeyRenewBefore         = "renewBefore"
	KeyKeyUsages           = "keyUsages"
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
	KeyPrivateKeyAlgorithm = "privateKey.algorithm"
	KeyPrivateKeySize      = "privateKey.size"
	KeyIssuerDir           = "issuer.dir"
	KeyIssuerPublicKey     = "issuer.publicKey"
	KeyIssuerPrivateKey    = "issuer.privateKey"
)

var (
	ErrOpenCertificateRequestFile = errors.New("open file")
	ErrReadCertificateRequestFile = errors.New("read file")
	ErrInvalidKeyUsages           = errors.New("invalid key usages")
	ErrInvalidExtKeyUsages        = errors.New("invalid ext key usages")
	ErrInvalidIPAddress           = errors.New("invalid ip addresses")
	ErrMissingMandatoryField      = errors.New("missing mandatory field")
)

type PrivateKey struct {
	Algorithm string
	Size      int
}

type IssuerPath struct {
	PublicKey  string
	PrivateKey string
}

type CertificateRequest struct {
	OutCertPath         string
	OutKeyPath          string
	OutCAPath           string
	CommonName          string
	IsCA                bool
	Countries           []string
	Organizations       []string
	OrganizationalUnits []string
	Localities          []string
	Provinces           []string
	StreetAddresses     []string
	PostalCodes         []string
	Duration            time.Duration
	RenewBefore         time.Duration
	KeyUsage            x509.KeyUsage
	ExtKeyUsage         []x509.ExtKeyUsage
	DNSNames            []string
	IPAddresses         []net.IP
	PrivateKey          PrivateKey
	IssuerPath          IssuerPath
}

func LoadCertificateRequest(path string) (CertificateRequest, error) {
	conf := viper.New()
	file, err := os.Open(path)
	if err != nil {
		return CertificateRequest{}, fmt.Errorf(format.WrapErrors, ErrOpenCertificateRequestFile, err)
	}
	ext, err := config.GetExtension(path)
	if err != nil {
		return CertificateRequest{}, err
	}
	conf.SetConfigType(ext)
	if err := conf.ReadConfig(file); err != nil {
		return CertificateRequest{}, fmt.Errorf(format.WrapErrors, ErrReadCertificateRequestFile, err)
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
	conf.SetDefault(KeyIssuerPublicKey, "ca.crt")
	conf.SetDefault(KeyIssuerPrivateKey, "ca.key")

	outDir := conf.GetString(KeyOutDir)
	if outDir == "" {
		return CertificateRequest{}, fmt.Errorf(format.WrapErrorString, ErrMissingMandatoryField, KeyOutDir)
	}

	issuerDir := conf.GetString(KeyIssuerDir)
	var issuerPath IssuerPath
	if issuerDir != "" {
		issuerPubKeyPath := filepath.Join(issuerDir, conf.GetString(KeyIssuerPublicKey))
		issuerPrivKeyPath := filepath.Join(issuerDir, conf.GetString(KeyIssuerPrivateKey))
		issuerPath = IssuerPath{PublicKey: issuerPubKeyPath, PrivateKey: issuerPrivKeyPath}
	}

	req := CertificateRequest{
		OutCertPath:         filepath.Join(outDir, conf.GetString(KeyOutCert)),
		OutKeyPath:          filepath.Join(outDir, conf.GetString(KeyOutKey)),
		OutCAPath:           filepath.Join(outDir, conf.GetString(KeyOutCA)),
		CommonName:          conf.GetString(KeyCommonName),
		IsCA:                conf.GetBool(KeyIsCA),
		Countries:           conf.GetStringSlice(KeyCountries),
		Organizations:       conf.GetStringSlice(KeyOrganizations),
		OrganizationalUnits: conf.GetStringSlice(KeyOrganizationalUnits),
		Localities:          conf.GetStringSlice(KeyLocalities),
		Provinces:           conf.GetStringSlice(KeyProvinces),
		StreetAddresses:     conf.GetStringSlice(KeyStreetAddresses),
		PostalCodes:         conf.GetStringSlice(KeyPostalCodes),
		Duration:            conf.GetDuration(KeyDuration),
		RenewBefore:         conf.GetDuration(KeyRenewBefore),
		PrivateKey:          PrivateKey{Algorithm: conf.GetString(KeyPrivateKeyAlgorithm), Size: conf.GetInt(KeyPrivateKeySize)},
		IssuerPath:          issuerPath,
	}

	for _, s := range conf.GetStringSlice(KeyKeyUsages) {
		keyUsage, err := findKeyUsage(s)
		if err != nil {
			return CertificateRequest{}, fmt.Errorf(format.WrapErrorString, ErrInvalidKeyUsages, s)
		}
		req.KeyUsage |= keyUsage
	}

	for _, s := range conf.GetStringSlice(KeyExtKeyUsages) {
		extKeyUsage, err := findExtKeyUsage(s)
		if err != nil {
			return CertificateRequest{}, fmt.Errorf(format.WrapErrorString, ErrInvalidExtKeyUsages, s)
		}
		req.ExtKeyUsage = append(req.ExtKeyUsage, extKeyUsage)
	}

	for _, dnsName := range conf.GetStringSlice(KeyDNSNames) {
		req.DNSNames = append(req.DNSNames, dnsName)
	}

	for _, s := range conf.GetStringSlice(KeyIPAddresses) {
		ipAddr := net.ParseIP(s)
		if ipAddr == nil {
			return CertificateRequest{}, fmt.Errorf(format.WrapErrorString, ErrInvalidIPAddress, s)
		}
		req.IPAddresses = append(req.IPAddresses, ipAddr)
	}

	return req, nil
}

func findKeyUsage(s string) (x509.KeyUsage, error) {
	switch strings.ToLower(s) {
	case "digital signature":
		return x509.KeyUsageDigitalSignature, nil
	case "content commitment":
		return x509.KeyUsageContentCommitment, nil
	case "key encipherment":
		return x509.KeyUsageKeyEncipherment, nil
	case "data encipherment":
		return x509.KeyUsageDataEncipherment, nil
	case "key agreement":
		return x509.KeyUsageKeyAgreement, nil
	case "cert sign":
		return x509.KeyUsageCertSign, nil
	case "crl sign":
		return x509.KeyUsageCRLSign, nil
	case "encipher only":
		return x509.KeyUsageEncipherOnly, nil
	case "decipher only":
		return x509.KeyUsageDecipherOnly, nil
	}
	return 0, ErrInvalidKeyUsages
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
	return 0, ErrInvalidExtKeyUsages
}
