# Python Envelope Encryption

This is a command-line tool that can encrypt files using
[Envelope Encryption](https://cloud.google.com/kms/docs/envelope-encryption).

It shows how you can use Tink to encrypt data with a newly generated *data
encryption key* (DEK) which is wrapped with a KMS key. The data will be
encrypted with AES256 GCM using the DEK and the DEK will be encrypted with the
KMS key and stored alongside the ciphertext.

The CLI takes 5 arguments:
* mode: "encrypt" or "decrypt" to indicate if you want to encrypt or decrypt.
* gcp-credentials: Name of the file with the GCP credentials in JSON format.
* key-uri: The URI for the key to be used for envelope encryption.
* input-file: Read the input from this file.
* output-file: Write the result to this file.

## Build and Run

### Bazel

```shell
git clone https://github.com/google/tink
cd tink/examples/python
bazel build ...
```

Using the test credentials you can then encrypt a file
```shell
echo "some data" >
testdata.txt ./bazel-bin/envelope/envelope encrypt testdata/credential.json
gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key
testdata.txt testdata.txt.encrypted```
or decrypt the file with
```shell
./bazel-bin/envelope/envelope decrypt testdata/credential.json
gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key
testdata.txt.encrypted testdata.txt decrypt
```

### Pip package

```shell
git clone https://github.com/google/tink
cd tink/python
pip3 install .
```

You can then encrypt the file
```shell
echo "some data" > testdata.txt
python3 envelope.py testdata/credential.json
gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key
testdata.txt testdata.txt.encrypted
```
