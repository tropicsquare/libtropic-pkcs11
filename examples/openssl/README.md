# OpenSSL examples

This folder contains example integration of TROPIC01 into OpenSSL via PKCS11 provider backend.

To run this, you will need to install libp11:

[libp11](https://github.com/OpenSC/libp11)

You can either build and install the library from source (see INSTALL.md in the `libp11` repository),
or install it from package manager. E.g. on Ubuntu:

```
apt-get install libengine-pkcs11-openssl
```

After installing, you will need to locate path to the `pkcs11prov.so` shared library.
E.g.:
```
/usr/lib/x86_64-linux-gnu/engines-3/pkcs11prov.so
```

The path to this library needs to be set in `openssl_libp11_provider.cnf` for `module` attribute.

## Examples

The `ListProviders.sh` script verifies OpenSSL was able to load the PKCS11 provider.

The `Sign.sh` signs with TROPIC01 with a P256 Key in an ECC Key slot. This example requires to
have ECC Key in an ECC Key slot. You can use `pkcs11-tool` to generate the key in the ECC Key Slot.

The `Verify.sh` reads public Key from an ECC Key slots and verifies message signature with such
public key.
