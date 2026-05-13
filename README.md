# certificate-translator

A Juju charm that bridges the legacy OpenStack `tls-certificates` interface with
the modern TLS certificate interface used by charms such as `lego`, `vault`, and
`self-signed-certificates`.

## Overview

OpenStack charms (e.g. Keystone, Nova, Neutron) use an older version of the
`tls-certificates` interface where certificate requests are expressed as JSON
objects containing a common name (CN) and subject alternative names (SANs). Modern
certificate providers use a CSR-based interface.

This charm acts as a translator:

1. **Legacy side** (`legacy-certificates`): Receives certificate requests from
   OpenStack charms in the old format.
2. **Modern side** (`certificates`): Generates CSRs and forwards them to a modern
   TLS provider.
3. **Response**: When the modern provider returns a certificate, the charm
   translates it back to the legacy format and publishes it to the requesting
   OpenStack charm.

## Usage

Deploy the charm alongside a modern TLS provider and relate them:

```bash
juju deploy self-signed-certificates
juju deploy certificate-translator
juju relate certificate-translator:certificates self-signed-certificates:certificates
```

Then relate your OpenStack charms to the translator's legacy side:

```bash
juju relate keystone:certificate-translator legacy-certificates
```

## Relations

- **`certificates`** (requires): Connects to a modern TLS certificate provider.
- **`legacy-certificates`** (provides): Accepts connections from OpenStack charms
  using the legacy `tls-certificates` interface.

## Features

- Handles multiple legacy charms simultaneously.
- Automatically requests certificate renewal when certificates approach expiry.
- Cleans up modern CSR requests when legacy relations are broken.

## Testing

Run unit tests with:

```bash
tox -e unit
```

Run integration tests with:

```bash
tox -e integration
```

## See also

- [Contributing](CONTRIBUTING.md)
- [Juju documentation](https://documentation.ubuntu.com/juju/3.6/howto/manage-charms/)
