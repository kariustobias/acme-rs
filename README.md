# acme-rs
An ACME Client for Let's Encrypt written in Rust to request SSL/TLS certificates.

## Contents
 - [Features](#Features)
 - [Installation](#Installation)
 - [Usage](#Usage)
 - [Options](#Options)

## Features
- acme-rs in its current state does only support the http challenge. The port 80 must not be blocked. <br>
- You have the option to generate you key-pair for the certificate first before running executing the client. <br>
- By default, acme-rs will send the request to the URL https://acme-v02.api.letsencrypt.org/directory. However, you can manually change the ACME Server URL by using the "--server" flag.

## Installation

## Usage
acme-rs is using the openssl rust wrapper crate to generate keys and the csr.

The client will store the certificate and the certificate chain in the files "cert.pem" and "chain.pem"

### Request a certificate
You can request a certificate by using the following command: <br>
acme-rs [OPTIONS] --domain <domain>

## Options
By running the command "acme-rs --help" you can get an overview of all the commands available.

```
USAGE:
    acme-rs [OPTIONS] --domain <domain>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -d, --domain <domain>              The domain to register the certificate for
    -p, --private-key <private-key>    An optional private key file (PEM format) to load the keys
                                       from
    -p, --public-key <public-key>      An optional public key file (PEM format) to load the keys
                                       from
    -s, --server <server>              The ACME server's URL
```

