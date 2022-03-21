# Kernel Public Key Test Module
Simple kernel module to test loading public key and verifying signature with loaded public key.

## Install Kernel Headers
To build kernel module you need to install kernel headers package.
On debian machines you may install kernel headers with following command.
```sh
sudo apt install linux-headers-$(uname -r)
```

## Building Module
To install module you need to have root access. Run `make` command to build and verify output.
```sh
[elmurod@smartnode:epk{main}]$ make
make[1]: Entering directory '/usr/src/linux-headers-5.4.0-100-generic'
  Building modules, stage 2.
  MODPOST 1 modules
make[1]: Leaving directory '/usr/src/linux-headers-5.4.0-100-generic'pk/epk.mod.o
  LD [M]  /home/elmurod/tizen/github/e-talipov/epk/epk.ko
make[1]: Leaving directory '/usr/src/linux-headers-5.4.0-100-generic'
```
To install module and change file permissions of `/sys/kernel/epk/verify` run `make test`

## Verify Key Load
To check loaded key run following command
```sh
cat /sys/kernel/epk
```
Which should give following or similar output 
```sh
574072203 : epk-verification-key
```
Or you can also check in key list with following command
```sh
sudo cat /proc/keys | grep epk
```
Output should be something like below
```sh
22685c40 I------     1 perm 1f030000     0     0 keyring   .epk_custom: 1
38b5aca8 I------     2 perm 1f030000     0     0 asymmetri epk-verification-key: X509.rsa []
```

## Verify Signature
Go to `data` folder, generate signature for `sample.bin` and verify signature by running folowing command.
You can see verification result as `PASS` or `FAIL`
```sh
elmurod@smartnode:data{main}]$ ./test.sh
Set Data: sha512 /home/elmurod/tizen/github/e-talipov/epk/data/sample.bin /home/elmurod/tizen/github/e-talipov/epk/data/sample.sgn
Get Result:
/home/elmurod/tizen/github/e-talipov/epk/data/sample.bin /home/elmurod/tizen/github/e-talipov/epk/data/sample.sgn : PASS
```

## Generate and Update Public Key
Go to `data` folder and first prepare configurations in `key.config` file, and then
run `genkey.sh`;

This will generate asymmetric key pair, X.509 certificate and `epk-public-key.h` file.

## Show Certificate Information
```sh
openssl x509 -text -noout -in keys/EPK-X509-CERTIFICATE.pem
```