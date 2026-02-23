# Using libtropic-pkcs11 with OpenSSH

This tutorial shows how to use libtropic-pkcs11 provider to authenticate to an SSH server using keys
stored on a TROPIC01 USB DevKit on Linux.

The flow is similar to standard SSH public-key authentication, but the private key never leaves
the TROPIC01 device, so the TROPIC01 USB DevKit acts as your hardware SSH key.

## Prerequisites

You will need:
- TROPIC01 USB DevKit
- OpenSSH client
- OpenSSL
- `pkcs11-tool` (from OpenSC)
- CMake, `make` and `gcc` to build `libtropic-pkcs11`

You will also need a remote machine running an OpenSSH server to which you want to connect. The
examples below assume the remote host is `username@host`.

Install dependencies as needed:

- Fedora: `sudo dnf install openssh openssl opensc cmake make gcc`
- Debian/Ubuntu: `sudo apt update && sudo apt install -y openssh-client openssl opensc cmake make gcc`

For other distributions, check your package manager or build from source.

## Overview

1. Build the provider and ensure `libtropic_pkcs11.so` is available in your current directory.
2. Generate a key on the token with `pkcs11-tool`.
3. Export the public key and convert it to OpenSSH format.
4. Copy the public key to the server.
5. Connect to the server.

## Step-by-step guide

Follow these steps in order. Commands assume you run them from the directory containing the built
`libtropic_pkcs11.so` provider; using the full path to the provider (recommended) avoids confusion.
 
**1. Build the `libtropic_pkcs11.so` provider:**

Follow instructions in the [root README.md](../../README.md).

**2. Generate the key pair on the TROPIC01 (P-256):**

```sh
# Generate a P-256 key pair on the token (run from the build directory or use an absolute path)
pkcs11-tool --module ./libtropic_pkcs11.so --keypairgen --key-type EC:secp256r1 --id "0"
```

**3. Extract the public key and convert it to an OpenSSH-compatible format:**

```sh
# Export public key (DER)
pkcs11-tool --module ./libtropic_pkcs11.so --read-object --type pubkey --id "0" -o my_p256_key.der.pub

# Convert DER -> PEM -> OpenSSH text format
openssl pkey -in my_p256_key.der.pub -inform DER -pubin -out my_p256_key.pem.pub -outform PEM
ssh-keygen -i -m PKCS8 -f my_p256_key.pem.pub > my_p256_key.pub

# Clean up intermediate files
rm my_p256_key.der.pub my_p256_key.pem.pub
```

**4. Copy the resulting `my_p256_key.pub` to the remote server's `~/.ssh/authorized_keys`.**

Options to upload the key:

- Manually append the contents of `my_p256_key.pub` to `~/.ssh/authorized_keys` on the server.
- Use `ssh-copy-id` (recommended when available):

```sh
ssh-copy-id -f -i ./my_p256_key.pub username@host
```

Note: `ssh-copy-id` requires the public key be in OpenSSH text format — the `ssh-keygen -i ...`
step above produces the correct format.

**5. Log in using OpenSSH with the PKCS#11 provider. When asked for PIN, do not enter anything and press Enter to continue (PIN is not used).**

```sh
ssh -I ./libtropic_pkcs11.so username@host
```

You should see output similar to:

```
Found PUBLIC KEY in ECC slot 0 (handle=0x30000, curve=1)
Enter PIN for 'TR01-C2S-X210-0C01':
Found PRIVATE KEY in ECC slot 0 (handle=0x20000, curve=1)
username@host:~ $
```

If you previously used password authentication, you should no longer be prompted for the password
once the public key is accepted by the server. If you have other SSH keys configured locally,
temporarily moving them can help verify you're authenticating with the TROPIC01 key.

## Common problems and troubleshooting

Quick checklist before troubleshooting:

- Verify you use the correct, OpenSSH-formatted public key (`my_p256_key.pub`).
- Use the correct path to the provider in `ssh -I ./libtropic_pkcs11.so ...`.

### I cannot compile the module

Check the repository [README.md](../../README.md) and the [Libtropic FAQ](https://tropicsquare.github.io/libtropic/latest/faq/).

### SSH still prompts for password
Symptom:

```
$ ssh -I ./libtropic_pkcs11.so username@host
username@host's password:
```

This indicates the server did not accept the key. Common causes and checks:

- Permissions on the server: `authorized_keys` should be `600`, `.ssh` directory `700`.
- Server config: ensure `PubkeyAuthentication yes` is set in `/etc/ssh/sshd_config` and the
  SSH server daemon was reloaded.
- Key format: confirm `my_p256_key.pub` contains the OpenSSH public-key text produced by
  `ssh-keygen -i -m PKCS8 ...`.
- Device: if you have multiple TROPIC01 devices, use the same one the key was generated on.
- Libtropic version:
    - Build `libtropic-pkcs11` against the Libtropic that is pinned in this repository. Older Libtropic versions contain an ECDSA bug that produces invalid signatures and causes SSH authentication to fail, so always use the pinned version from this repo.

### Permission denied (publickey)
Symptom:

```
$ ssh -I ./libtropic_pkcs11.so username@host
Permission denied (publickey).
```

You will see this error if both apply:
- Password-based authentication is disabled on your server.
- Key (signature done using the key) was not accepted.

Causes are similar to the [issue with password](#ssh-still-prompts-for-password).

### Other errors
Try these checks:

- Turn on PKCS#11 logging during build: `cmake -DLT_PKCS11_LOG_EN=ON ..` and rebuild.
- Run SSH with high verbosity: `ssh -vvv -I ./libtropic_pkcs11.so username@host` and
  inspect the logs.

If you still cannot identify the issue, collect the verbose SSH output and any PKCS#11 logs and
open an issue or ask for help with those logs attached. Do not forget to strip any sensitive information.