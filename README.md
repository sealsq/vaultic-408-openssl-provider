
# OpenSSL Provider for SealSQ Secure Elements Vault-IC 408

A provider, in OpenSSL terms, is a unit of code that provides one or more

implementations for various operations for diverse algorithms that one might

want to perform.

the following functionality can be made available over the OpenSSL provider here (sss provider).

- EC sign
- RSA sign
- Random generator
- TLS 1.2 demonstration (RSA & ECC)

The OpenSSL provider is compatible with OpenSSL versions 3.x

OpenSSL provider is tested on Raspberry Pi 4 Model B

## Getting Started on Raspberry Pi

### Prerequisites

- Raspberry pi with Raspberry Pi OS

- cmake installed - sudo apt-get install cmake

- OpenSSL 3.x installed

- libssl installed - sudo apt-get install cmake libssl-dev

- TLS_VIC408_***_RASPBERRY connected to Raspberry Pi

### Build

Run the commands below to build OpenSSL provider for VaultIC 408 secure element

```console
git clone --recurse-submodules https://github.com/sealsq/vaultic-408-openssl-provider.git
cd vaultic-408-openssl-provider
mkdir build
cd build
cmake ..
cmake --build .
cmake --install . (you may need use sudo)
```

## Testing Seal SQ OpenSSL Provider for VIC408

### Random Number Generation
```console
openssl rand --provider /usr/local/lib/libsealsq_vic408_provider.so -hex 32
```

### ECDSA - Sign Operation
```console
openssl pkeyutl --provider /usr/local/lib/libsealsq_vic408_provider.so --provider default -inkey vaulticKey:ecc:0xEC:0x08:0x07 -sign -rawin -in input.txt -out signature.txt -digest sha256
```

### ECDSA - Verify Operation with OpenSSL
```console
openssl x509 -in ../lib/libVaultIC/408/certificate/s_client/deviceCert_ECC.pem -pubkey -noout -out certificate.pub.pem
openssl dgst -sha256 -verify certificate.pub.pem -signature signature.txt input.txt
```

### RSA- Sign Operation
```console
openssl pkeyutl --provider /usr/local/lib/libsealsq_vic408_provider.so --provider default -inkey vaulticKey:rsa:0x20:0x02:0x01 -sign -rawin -in input.txt -out signature.txt -digest sha256
```

### RSA - Verify Operation with OpenSSL
```console
openssl x509 -in ../lib/libVaultIC/408/certificate/s_client/deviceCert_RSA.pem -pubkey -noout -out certificate.pub.pem
openssl dgst -sha256 -verify certificate.pub.pem -signature signature.txt input.txt
```

## TLS Client example using provider
This section explains how to set-up a TLS using the OpenSSL Provider for VaultIC on the client side to identificate the device.

The keypair and certificate used to identify the client is previously provisioned in the Secure Element. (see DEVKIT DEMO)

The keypair and certificate are to identify the server are clear

### TLS1.2 client example using EC key

  Personalisation in VAULT-IC 408 :
  ECC private key : index group = ECh keyindex = 08h
  ECC public key : index group ECh keyindex 07h
  associated certificate : index 00h
  
  Run Server as
```console
cd vaultic-408-openssl-provider/lib/libVaultIC/408/certificate/s_server/
openssl s_server -accept 8080  -CAfile rootCACert_ECC.pem -no_ssl3  -cert serverCert_ECC.pem -key serverKey_ECC.pem -Verify 2 -msg -verify_return_error
```

In another Terminal run Client as

```console
openssl s_client --provider /usr/local/lib/libsealsq_vic408_provider.so --provider default -connect 127.0.0.1:8080 -tls1_2 -cert vaulticCert:0x00 -key vaulticKey:ecc:0xEC:0x08:0x07 -state -msg
```
  
### TLS1.2 client example using RSA keys

  Personalisation in VAULT-IC 408 :
  RSA private key : index group 20h keyindex 02h
  RSA public key : index group 20h keyindex 01h
  associated certificate : index 00h
  
Run Server as
```console
cd vaultic-408-openssl-provider/lib/libVaultIC/408/certificate/s_server/
openssl s_server -accept 8080  -CAfile rootCACert_RSA.pem -no_ssl3  -cert serverCert_RSA.pem -key serverKey_RSA.pem -Verify 1 -msg -verify_return_error
```

Run Client as
```console
openssl s_client --provider /usr/local/lib/libsealsq_vic408_provider.so --provider default -connect 127.0.0.1:8080 -tls1_2 -cert vaulticCert:0x00 -key vaulticKey:rsa:0x20:0x02:0x01 -state -msg
```