# Tink for Go HOW-TO

This document contains instructions for common tasks in
[Tink](https://github.com/google/tink). Example code snippets for these tasks
and API documentation can be found on
[pkg.go.dev](https://pkg.go.dev/github.com/google/tink/go).

## Setup instructions

To install Tink locally run:

```sh
go get github.com/google/tink/go/...
```

to run all the tests locally:

```sh
cd $GOPATH/go/src/github.com/google/tink/go
go test ./...
```

Golang Tink API also supports [Bazel](https://www.bazel.build) builds. To run
the tests using bazel:

```sh
cd $GOPATH/go/src/github.com/google/tink/go
bazel build ... && bazel test ...
```

## Generating new keys and keysets

To take advantage of key rotation and other key management features, you usually
do not work with single keys, but with keysets. Keysets are just sets of keys
with some additional parameters and metadata.

Internally Tink stores keysets as Protocol Buffers, but you can work with
keysets via a wrapper called a keyset handle. You can generate a new keyset and
obtain its handle using a KeyTemplate. KeysetHandle objects enforce certain
restrictions that prevent accidental leakage of the sensitive key material.

```go
package main

import (
  "fmt"
  "log"

  "github.com/google/tink/go/aead"
  "github.com/google/tink/go/keyset"
)

func main() {
  // Other key templates can also be used.
  kh, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
  if err != nil {
    log.Fatal(err)
  }

  fmt.Println(kh.String())
}

```

Key templates are available for MAC, digital signatures, AEAD encryption, DAEAD
encryption and hybrid encryption.

Key Template Type | Key Template
----------------- | ------------------------------------------------
AEAD              | aead.AES128CTRHMACSHA256KeyTemplate()
AEAD              | aead.AES128GCMKeyTemplate()
AEAD              | aead.AES256CTRHMACSHA256KeyTemplate()
AEAD              | aead.AES256GCMKeyTemplate()
AEAD              | aead.ChaCha20Poly1305KeyTemplate()
AEAD              | aead.XChaCha20Poly1305KeyTemplate()
DAEAD             | daead.AESSIVKeyTemplate()
MAC               | mac.HMACSHA256Tag128KeyTemplate()
MAC               | mac.HMACSHA256Tag256KeyTemplate()
MAC               | mac.HMACSHA512Tag256KeyTemplate()
MAC               | mac.HMACSHA512Tag512KeyTemplate()
Signature         | signature.ECDSAP256KeyTemplate()
Signature         | signature.ECDSAP384KeyTemplate()
Signature         | signature.ECDSAP521KeyTemplate()
Hybrid            | hybrid.ECIESHKDFAES128GCMKeyTemplate()
Hybrid            | hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate()

To avoid accidental leakage of sensitive key material, you should avoid mixing
keyset generation and usage in code. To support the separation of these
activities Tink provides a command-line tool, [Tinkey](TINKEY.md), which can be
used for common key management tasks.

## Storing and loading existing keysets

After generating key material, you might want to persist it to a storage system.
Tink supports encrypting and persisting the keys to any io.Writer and io.Reader
implementations.

```go
package main

import (
  "fmt"
  "log"

  "github.com/google/tink/go/aead"
  "github.com/google/tink/go/core/registry"
  "github.com/google/tink/go/integration/gcpkms"
  "github.com/google/tink/go/keyset"
)

const (
  // Change this. AWS KMS, Google Cloud KMS and HashiCorp Vault are supported out of the box.
   keyURI = "gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar"
  credentialsPath = "credentials.json"
)

func main() {
  // Generate a new key.
  kh1, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
  if err != nil {
    log.Fatal(err)
  }

  // Fetch the master key from a KMS.
  gcpClient, err := gcpkms.NewClientWithCredentials(keyURI, credentialsPath)
  if err != nil {
    log.Fatal(err)
  }
  registry.RegisterKMSClient(gcpClient)
  masterKey, err := gcpClient.GetAEAD(keyURI)
  if err != nil {
    log.Fatal(err)
  }

  // An io.Reader and io.Writer implementation which simply writes to memory.
  memKeyset := &keyset.MemReaderWriter{}

  // Write encrypts the keyset handle with the master key and writes to the
  // io.Writer implementation (memKeyset). We recommend that you encrypt the
  // keyset handle before persisting it.
  if err := kh1.Write(memKeyset, masterKey); err != nil {
    log.Fatal(err)
  }

  // Read reads the encrypted keyset handle back from the io.Reader
  // implementation and decrypts it using the master key.
  kh2, err := keyset.Read(memKeyset, masterKey)
  if err != nil {
    log.Fatal(err)
  }
}
```

## AEAD

The AEAD primitive (authenticated encryption with associated data) is the most
common primitive to ***encrypt*** data. It is symmetric, and using the same key
for encryption and decryption.

Check out the
[AEAD examples](https://pkg.go.dev/github.com/google/tink/go/aead#example-package).
The `Play` button at the corner right allows you to run them on the Go
Playground.

## Deterministic AEAD

The Deterministic AEAD primitive (authenticated encryption with associated data)
is used to ***deterministically encrypt*** data. It is symmetric, and using the
same key for encryption and decryption.

Unlike AEAD, implementations of this interface are not semantically secure,
because encrypting the same plaintext always yields the same ciphertext.

Check out the
[Deterministic AEAD examples](https://pkg.go.dev/github.com/google/tink/go/daead#example-package).
The `Play` button at the corner right allows you to run them on the Go
Playground.

## MAC

The MAC primitive allows you to ensure that nobody tampers with data you own. It
is symmetric, and using the same key for authentication and verification.

Check out the
[MAC examples](https://pkg.go.dev/github.com/google/tink/go/mac#example-package).
The `Play` button at the corner right allows you to run them on the Go
Playground.

## Digital signature

The digital signature primitives allow you to ensure that nobody tampers with
your data. It is asymmetric, and hence comes with a pair of keys (public key and
private key). The private key allows to sign messages, and the public key allows
to verify.

Check out the
[digital signature examples](https://pkg.go.dev/github.com/google/tink/go/signature#example-package).
The `Play` button at the corner right allows you to run them on the Go
Playground.

## Hybrid encryption

The hybrid encryption primitives allow you to encrypt data with a public key.
Only users with the secret key will be able to decrypt the data.

Check out the
[hybrid encryption examples](https://pkg.go.dev/github.com/google/tink/go/hybrid#example-package).
The `Play` button at the corner right allows you to run them on the Go
Playground.

## Envelope encryption

Via the AEAD interface, Tink supports
[envelope encryption](KEY-MANAGEMENT.md#envelope-encryption).

For example, you can perform envelope encryption with a Google Cloud KMS key at
`gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar`
using the credentials in `credentials.json` as follows:

```go
package main

import (
  "encoding/base64"
  "fmt"

  "github.com/google/tink/go/aead"
  "github.com/google/tink/go/core/registry"
  "github.com/google/tink/go/integration/gcpkms"
  "github.com/google/tink/go/keyset"
)

const (
   // Change this. AWS KMS, Google Cloud KMS and HashiCorp Vault are supported out of the box.
   keyURI          = "gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar"
   credentialsPath = "credentials.json"
)

func main() {
  gcpclient, err := gcpkms.NewClientWithCredentials(keyURI, credentialsPath)
  if err != nil {
    log.Fatal(err)
  }
  registry.RegisterKMSClient(gcpclient)

  dek := aead.AES128CTRHMACSHA256KeyTemplate()
  kh, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(keyURI, dek))
  if err != nil {
    log.Fatal(err)
  }

  a, err := aead.New(kh)
  if err != nil {
    log.Fatal(err)
  }

  msg := []byte("this message needs to be encrypted")
  aad := []byte("this data needs to be authenticated, but not encrypted")
  ct, err := a.Encrypt(msg, aad)
  if err != nil {
    log.Fatal(err)
  }

  pt, err := a.Decrypt(ct, aad)
  if err != nil {
    log.Fatal(err)
  }

  fmt.Printf("Ciphertext: %s\n", base64.StdEncoding.EncodeToString(ct))
  fmt.Printf("Original  plaintext: %s\n", msg)
  fmt.Printf("Decrypted Plaintext: %s\n", pt)
}
```
