# uCerts - Automated private TLS Certificate Management Tool

uCerts is a powerful and user-friendly tool designed to simplify the generation of private TLS certificates,
including self-signed root CAs, and manage their automatic renewal. With uCerts, you can streamline the process of
securing your applications with trusted certificates, ensuring data integrity and secure communication.

[![Go Report Card](https://goreportcard.com/badge/github.com/goten4/ucerts?)](https://goreportcard.com/report/github.com/goten4/ucerts)
[![Build Status](https://github.com/goten4/ucerts/actions/workflows/go.yml/badge.svg)](https://github.com/goten4/ucerts/actions)
[![codecov](https://codecov.io/gh/goten4/ucerts/graph/badge.svg?token=LDW52PRVSN)](https://codecov.io/gh/goten4/ucerts)
[![release](https://img.shields.io/github/release-pre/goten4/ucerts.svg)](https://github.com/goten4/ucerts/releases)
[![Releases](https://img.shields.io/github/downloads/goten4/ucerts/total.svg)](https://github.com/goten4/ucerts/releases)

## Features

- **Certificate Generation**: Easily generate private TLS certificates and self-signed root Certificate Authorities(CAs) for your applications.
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

uCerts requires a configuration file, the supported extensions are: `json`, `toml`, `yaml`, `yml`, `properties`,
`props`, `prop`, `hcl`, `tfvars`, `dotenv`, `env`, `ini`.

You will find an example configuration file in yaml at [example/etc/config.yaml](example/etc/config.yaml).

In this configuration file, you must specify the path or paths to the `Certificate Requests`. These are files that
describe the parameters of the certificates that uCerts needs to generate and renew. You will find examples of
`Certificate Requests` in the directory [example/tls/requests](example/tls/requests).

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

### Example

To test the example files:

```shell
$ make build
$ ./ucerts -c example/etc/config.yaml
```

## Contributions

Contributions to uCerts are welcome! If you find a bug or have an enhancement in mind, please submit an issue or a pull request.

## License

This project is licensed under the GPL-3.0 License. See the [LICENSE](LICENSE) file for details.
