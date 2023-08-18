# uCerts - Automated private TLS Certificate Management Tool

uCerts is a powerful and user-friendly tool designed to simplify the generation of private TLS certificates, including self-signed root CAs, and manage their automatic renewal. With uCerts, you can streamline the process of securing your applications with trusted certificates, ensuring data integrity and secure communication.

## Features

- **Certificate Generation**: Easily generate private TLS certificates and self-signed root Certificate Authorities (CAs) for your applications.
- **Automated Renewal**: uCerts takes care of the automatic renewal of managed certificates, ensuring your services remain secure without manual intervention.
- **Configurable Options**: Customize certificate attributes and settings according to your application's requirements.

## Installation

uCerts is available on Linux, FreeBSD, macOS and Windows platforms.

* Binaries for Linux, FreeBSD, Windows and Mac are available as tarballs in the [release page](https://github.com/goten4/ucerts/releases).

* Via a Go install
```shell
go install github.com/goten4/uCerts
```

## Configuration

Here is an example of uCerts configuration file :
```yaml
shutdown:
  timeout: 10s # Duration to wait before exit program without wait for graceful stop
interval: 5m # uCerts checks periodically if a certificate should be renewed (default is 5m)
certificateRequests:
  paths:
    - /path/to/watch/for/certificate/requests/ca # Add path to root CAs first if you want to use it as issuer for certificates 
    - /path/to/watch/for/certificate/requests/server
    - /path/to/watch/for/certificate/requests/client
default: # TLS subject default values for all managed certificates 
  countries:
    - FR
  provinces:
    - France
  organizations:
    - uCerts
  organizationalUnits:
    - unit
  localities: 
    - Bordeaux
  streetAddresses:
    - Street
  postalCodes:
    - 3210
```

## Certificate requests

File `/opt/ucerts/requests/ca/ca.yaml`
```yaml
out:
  dir: /opt/ucerts/certs/ca
  cert: ca.crt
  key: ca.key
commonName: uCerts
duration: 87600h # 10 years
renewBefore: 8760h # 1 year
isCA: true
privateKey:
  algorithm: rsa
  size: 4096
```

File `/opt/ucerts/requests/server/localhost.yaml`
```yaml
out:
  dir: /opt/ucerts/certs/server
  cert: localhost.crt
  key: localhost.key
commonName: localhost
duration: 8760h # 1 year
renewBefore: 720h # 1 month
extKeyUsages:
  - server auth
dnsNames:
  - localhost
ipAddresses:
  - 127.0.0.1
  - 127.0.1.1
privateKey:
  algorithm: ecdsa
  size: 384
issuer:
  dir: /opt/ucerts/certs/ca
  cert: ca.crt
  key: ca.key
```

File `/opt/ucerts/requests/server/selfsigned.yaml`
```yaml
out:
  dir: /opt/ucerts/certs/server
  cert: selfsigned.crt
  key: selfsigned.key
commonName: localhost
duration: 8760h # 1 year
renewBefore: 720h # 1 month
extKeyUsages:
  - server auth
dnsNames:
  - localhost
ipAddresses:
  - 127.0.0.1
  - 127.0.1.1
```

File `/opt/ucerts/requests/client/client.yaml`
```yaml
out:
  dir: /opt/ucerts/certs/client
commonName: client
duration: 168h # 7 days
renewBefore: 144h # 6 days
extKeyUsages:
  - client auth
issuer:
  dir: /opt/ucerts/certs/ca
```

## Run

### Usage

```shell
Usage:
  ucerts [flags]
  ucerts [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  version     print version and exit

Flags:
  -c, --config string   provides the configuration file
  -h, --help            help for ucerts

Use "ucerts [command] --help" for more information about a command.
```

### Systemd

```shell
[Unit]
Description=uCerts Private TLS Certificate Management Tool
After=network.target

[Service]
Type=simple
User=ucerts
Group=ucerts
WorkingDirectory=/opt/ucerts
ExecStart=/opt/ucerts/bin/ucerts -c /opt/ucerts/etc/config.yaml
Restart=always

[Install]
WantedBy=default.target
```

## Contributions

Contributions to uCerts are welcome! If you find a bug or have an enhancement in mind, please submit an issue or a pull request.

## License

This project is licensed under the GPL-3.0 License. See the [LICENSE](LICENSE) file for details.
