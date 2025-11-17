# libp11

Instructions for compiling, installing, and using [libp11](https://github.com/OpenSC/libp11).

Official documentation, refer to the [original README](https://github.com/OpenSC/libp11/blob/master/README.md) and [INSTALL.md](https://github.com/OpenSC/libp11/blob/master/INSTALL.md).

## Understanding PKCS#11 Provider

### What is pkcs11prov?

The **pkcs11prov** (PKCS#11 provider) is an OpenSSL 3.x provider that allows OpenSSL to use PKCS#11 modules for cryptographic operations. It replaces the older "engine" API used in OpenSSL 1.x.


### OpenSSL Configuration File

To use the pkcs11prov provider, you need to configure OpenSSL.

**Linux**: Typically `/etc/ssl/openssl.cnf` or `~/.openssl/openssl.cnf` 

**macOS**: Use a custom config file or modify the system one

The configuration should include:

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
identity = pkcs11prov
module = /path/to/pkcs11prov.so
pkcs11_module = /path/to/your-pkcs11-module.so
debug_level = 7
activate = 1
```

**Important**: Update the paths in the configuration file to match your installation:
- `module`: Path to the pkcs11prov provider (e.g., `/usr/local/lib/ossl-modules/pkcs11prov.so`)
- `pkcs11_module`: Path to your PKCS#11 module (e.g., `/usr/lib/opensc-pkcs11.so`)

### Using a Custom Configuration File

You can use a custom OpenSSL configuration file:

```bash
export OPENSSL_CONF=/path/to/your/openssl.cnf
openssl list -providers
```

Or specify it on the command line:

```bash
openssl -config /path/to/your/openssl.cnf list -providers
```

## Testing the Installation

### 1. Verify Provider Installation

Check if the pkcs11prov provider is available:

```bash
openssl list -providers -verbose -provider pkcs11prov
```

Expected output:
```
Providers:
  pkcs11prov
    name: libp11 PKCS#11 provider (pkcs11prov)
    version: 0.4.16
    status: active
    ...
```

### 2. Verify Engine Installation (OpenSSL 1.x)

For OpenSSL 1.x, test the engine:

```bash
openssl engine pkcs11 -t
```

Expected output:
```
(pkcs11) pkcs11 engine
     [ available ]
```

### 3. Test Basic Functionality

A simple test that works without a token is generating random data:

```bash
# Using the provider (OpenSSL 3.x)
openssl rand -provider pkcs11prov -hex 32
```

**Note**: This command uses the PKCS#11 module's random number generator if available, but will fall back to OpenSSL's default RNG if no token is present.

## Basic Usage Examples

### Example 1: Generate Random Data

```bash
# Generate 64 random bytes in hexadecimal format
openssl rand -engine pkcs11 -hex 64

# Or with provider (OpenSSL 3.x)
openssl rand -provider pkcs11prov -hex 64
```

### Example 2: List Available Providers

```bash
openssl list -providers -verbose -provider pkcs11prov
```

### Example 3: Check OpenSSL Version and Modules

```bash
# Check OpenSSL version
openssl version -a

# List providers (OpenSSL 3.x)
openssl list -providers
```



- OpenSSL 1.x uses engines
- OpenSSL 3.x uses providers

## Resources

- **Official Repository**: https://github.com/OpenSC/libp11
- **Original README**: https://github.com/OpenSC/libp11/blob/master/README.md
- **Official INSTALL.md**: https://github.com/OpenSC/libp11/blob/master/INSTALL.md
- **Release Tarballs**: https://github.com/OpenSC/libp11/releases

