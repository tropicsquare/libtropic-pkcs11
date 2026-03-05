# Using libtropic-pkcs11 with OpenVPN

This tutorial shows how to use libtropic-pkcs11 provider to authenticate to an OpenVPN server using TROPIC01 USB DevKit on a Linux machine.

## Prerequisites

You will need:

- On the server machine:
    - OpenVPN server configured and running,
    - Certificate Authority manager (e.g., EasyRSA).

- On the client machine:
    - OpenVPN client,
    - TROPIC01 USB DevKit,
    - OpenSSL,
    - `pkcs11-tool` (from OpenSC),
    - `pkcs11prov` from `libp11`.
        - This is an OpenSSL 3.x provider plugin that allows transparent access to PKCS#11 modules.
    - CMake, `make` and `gcc` to build `libtropic-pkcs11`.

Notes:

- The server and the client can be the same machine.
- To quickly get OpenVPN server working, you can use [this Docker container](https://github.com/kylemanna/docker-openvpn). It also includes EasyRSA.
- You will need TROPIC01 USB DevKit with free first EC and certificate slot. It's best if you pick a devkit which you do not use for anything else or which does not contain any important key or certificate in the first slot.

## Overview

1. Build the provider and ensure `libtropic_pkcs11.so` is available in your current directory.
2. Generate a P-256 keypair on the token with `pkcs11-tool`.
3. Create a Certificate Signing Request (CSR) using OpenSSL with Libtropic PKCS#11 module.
4. Sign the request by your CA and retrieve resulting client certificate.
5. Write the client certificate to TROPIC01 using `pkcs11-tool`.
6. Prepare OpenVPN client configuration.
7. Connect to your OpenVPN server.

## Step-by-step guide

**1. Build the `libtropic_pkcs11.so` provider:**

Follow instructions in the [root README.md](../../README.md).

**2. Generate a key pair on the TROPIC01 (P-256):**

```sh
pkcs11-tool --module ./libtropic_pkcs11.so --keypairgen --key-type EC:secp256r1 --id "0"
```

Do not change the `id`. The implementation currently supports only the slot 0 for usage with OpenVPN.

**3. Create a CSR using OpenSSL**

In this step, we will create a Certificate Signing Request using OpenSSL. The Certificate Signing Request will be signed by TROPIC01.

You will need a custom OpenSSL configuration to enable Libtropic PKCS#11 support. We prepared a sample configuration
in the `openssl_pkcs11.cnf` file. You will need to check and modify the two lines in the `[pkcs11_sect]` section of the config:

```
module = /usr/lib64/ossl-modules/pkcs11.so # Path to pkcs11prov module (provided by libp11).
pkcs11-module-path = ./libtropic_pkcs11.so # Path to Libtropic PKCS#11 module.
```

After you have prepared the configuration for OpenSSL, create a CSR:

```sh
export OPENSSL_CONF="<path to openssl_pkcs11.cnf>"
openssl req -verbose -new \
            -provider pkcs11 \
            -sha256 \
            -subj "/CN=tropic01-client" \
            -key "pkcs11:id=%00;type=private" \
            -out tropic01-client.csr 
```

You can modify the `-subj` value as needed for your setup. 

If everything went correctly, you will have the CSR ready in the `tropic01-client.csr` file.

You can optionally verify the signature in the CSR is correct:

```sh
openssl req -in tropic01-client.csr -text -noout -verify
```

**4. Sign the request by your CA and retrieve resulting client certificate.**

Copy the CSR to your server. The signing process will differ depending on your CA management utility. For example, to sign the CSR using EasyRSA:

```sh
easyrsa import-req ./tropic01-client.csr tropic01-client
easyrsa sign-req client tropic01-client
```

If you used EasyRSA, the certificate will be exported to a `tropic01-client.crt` file. Copy the file to the client.

**5. Write the client certificate to TROPIC01**

You can store the client certificate in the TROPIC01, so you do not have to keep it on your client's filesystem.
For this, we will use OpenSSL and `pkcs11-tool`.

```sh
# Convert the certificate to the DER format.
# You can skip this if you already have the cert in the DER format
openssl x509 -in tropic01-client.crt -outform der -out tropic01-client.der
# Store the certificate to TROPIC01.
pkcs11-tool --module ./libtropic_pkcs11.so --write-object ./tropic01-client.der --type cert --label 0
```

Note: Do not change the label. It is used to identify certificate slot and currently the implementation supports only the slot 0 for usage with OpenVPN.

**6. Prepare OpenVPN client configuration**

This step will differ based on your OpenVPN server setup. We will focus on configuration options relevant for this tutorial: those are a private key and a client certificate.

Normally, the private key and client certificate are either present directly in the client config, or in
separate files on the client's filesystem. As our private key is in the TROPIC01, we will use Libtropic PKCS#11 provider.

First, we need to find PKCS#11 ID of our certificate we stored in TROPIC01 earlier:

```sh
openvpn --show-pkcs11-ids ./libtropic_pkcs11.so 
```

You will see output similar to the following:

```
Certificate
       DN:             CN=tropic01-client
       Serial:         A7402BA93662F68F6BA9E32B18A2A2BE
       Serialized id:  pkcs11:model=TR01-C2P-T103;token=TR01-C2P-T103-0A0A;manufacturer=TropicSquare;serial=2900011019192C;id=%00
```

We will need the **Serialized id**.

Modify the client configuration as follows:

- Remove or comment out `<key> ... </key>` and `<cert> ... </cert>` sections if present.
- Remove or comment out `cert ...` and `key ...` sections if present.
- Add PKCS#11 configuration:
    ```
    pkcs11-providers <absolute path to libtropic_pkcs11.so>
    pkcs11-id '<Serialized id you got from openvpn>'
    ```

Store the resulting configuration to a file, e.g., `tropic01-client.ovpn`.

Whole configuration can look like following (example):

```
client
nobind
dev tun
remote-cert-tls server

remote 127.0.0.1 1194 udp

pkcs11-providers /path/to/libtropic_pkcs11.so
pkcs11-id 'pkcs11:model=TR01-C2P-T103;token=TR01-C2P-T103-0A0A;manufacturer=TropicSquare;serial=2900011019192C;id=%00'

<ca>
-----BEGIN CERTIFICATE-----
# Your certificate
-----END CERTIFICATE-----
</ca>

key-direction 1
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
# Your TLS key
-----END OpenVPN Static key V1-----
</tls-auth>

redirect-gateway def1

```

**7. Connect to your OpenVPN with the configuration.**

Assuming you stored your client's configuration in `tropic01-client.ovpn`, run:  

```sh
sudo openvpn --config tropic01-client.ovpn
```

Now you should be connected to your OpenVPN server using TROPIC01 as an authenticator!

## Common problems and troubleshooting

### I cannot generate the key (`CKR_DEVICE_ERROR` or `CKR_DEVICE_MEMORY`)
The EC key slot 0 is already in use. If you do not need the key in the slot, delete it to make space:

```sh
pkcs11-tool --module ./libtropic_pkcs11.so --delete-object --type privkey --id <number>
```

### I cannot store the certificate (`CKR_DEVICE_ERROR` or `CKR_DEVICE_MEMORY`)

There are two possibilities:
- The certificate is too large. Size of single certificate slot is 4440 bytes (~4.3 KiB).
    - You probably used several optional fields. Try to minimize the contents of the certificate.
- The certificate slot 0 is already in use.
    - If you do not need the existing certificate, delete it to make space:
      ```sh
      pkcs11-tool --module ./libtropic_pkcs11.so --delete-object --type cert --id <number>
      ```