# Tink for Go HOW-TO

This document contains instructions and Go code snippets for common tasks in
[Tink](https://github.com/google/tink).

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

## GoDoc

Documentation for the Tink API can be found
[here](https://godoc.org/github.com/google/tink).

## Obtaining and using primitives

[_Primitives_](PRIMITIVES.md) represent cryptographic operations offered by
Tink, hence they form the core of Tink API. A primitive is just an interface
that specifies what operations are offered by the primitive. A primitive can
have multiple implementations, and you choose a desired implementation by
using a key of corresponding type (see the [this
section](KEY-MANAGEMENT.md#key-keyset-and-keysethandle) for details).

A list of primitives and their implemenations currently supported by Tink in
Golang can be found [here](PRIMITIVES.md#golang).

### AEAD

AEAD encryption assures the confidentiality and authenticity of the data. This
primitive is CPA secure.

```go
package main

import (
        "fmt"
        "log"

        "github.com/google/tink/go/aead"
        "github.com/google/tink/go/keyset"
)

func main() {

        kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
        if err != nil {
                log.Fatal(err)
        }

        a, err := aead.New(kh)
        if err != nil {
                log.Fatal(err)
        }

        ct, err := a.Encrypt([]byte("this data needs to be encrypted"), []byte("associated data"))
        if err != nil {
                log.Fatal(err)
        }

        pt, err := a.Decrypt(ct, []byte("associated data"))
        if err != nil {
                log.Fatal(err)
        }

        fmt.Printf("Cipher text: %s\nPlain text: %s\n", ct, pt)

}
```

### MAC

MAC computes a tag for a given message that can be used to authenticate a
message. MAC protects data integrity as well as provides for authenticity of the
message.

```go
package main

import (
        "fmt"
        "log"

        "github.com/google/tink/go/keyset"
        "github.com/google/tink/go/mac"
)

func main() {

        kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
        if err != nil {
                log.Fatal(err)
        }

        m, err := mac.New(kh)
        if err != nil {
                log.Fatal(err)
        }

        mac, err := m.ComputeMAC([]byte("this data needs to be MACed"))
        if err != nil {
                log.Fatal(err)
        }

        if m.VerifyMAC(mac, []byte("this data needs to be MACed")); err != nil {
                log.Fatal("MAC verification failed")
        }

        fmt.Println("MAC verification succeeded.")

}
```

### Deterministic AEAD

Unlike AEAD, implementations of this interface are not semantically secure,
because encrypting the same plaintext always yields the same ciphertext.

```go
package main

import (
        "bytes"
        "fmt"
        "log"

        "github.com/google/tink/go/daead"
        "github.com/google/tink/go/keyset"
)

func main() {

        kh, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
        if err != nil {
                log.Fatal(err)
        }

        d, err := daead.New(kh)
        if err != nil {
                log.Fatal(err)
        }

        ct1, err := d.EncryptDeterministically([]byte("this data needs to be encrypted"), []byte("additional data"))
        if err != nil {
                log.Fatal(err)
        }

        ct2, err := d.EncryptDeterministically([]byte("this data needs to be encrypted"), []byte("additional data"))
        if err != nil {
                log.Fatal(err)
        }

        if !bytes.Equal(ct1, ct2) {
                log.Fatal("cipher texts are not equal")
        }

        fmt.Print("Cipher texts are equal.\n")

        pt, err := d.DecryptDeterministically(ct1, []byte("additional data"))
        if err != nil {
                log.Fatal(err)
        }

        fmt.Printf("Plain text: %s\n", pt)

}
```

### Signature

To sign data using Tink you can use ECDSA or ED25519 key templates.

```go
package main

import (
        "fmt"
        "log"

        "github.com/google/tink/go/keyset"
        "github.com/google/tink/go/signature"
)

func main() {

        khPriv, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
        if err != nil {
                log.Fatal(err)
        }

        s, err := signature.NewSigner(khPriv)
        if err != nil {
                log.Fatal(err)
        }

        a, err := s.Sign([]byte("this data needs to be signed"))
        if err != nil {
                log.Fatal(err)
        }

        khPub, err := khPriv.Public()
        if err != nil {
                log.Fatal(err)
        }

        v, err := signature.NewVerifier(khPub)
        if err != nil {
                log.Fatal(err)
        }

        if err := v.Verify(a, []byte("this data needs to be signed")); err != nil {
                log.Fatal("signature verification failed")
        }

        fmt.Println("Signature verification succeeded.")

}
```

### Hybrid encryption and decryption

The functionality of Hybrid Encryption is represented as a pair of primitives
(interfaces):

 * `HybridEncrypt` for encryption of data
 * `HybridDecrypt` for decryption

Implementations of these interfaces are secure against adaptive chosen
ciphertext attacks.

In addition to plaintext, the encryption takes an extra parameter, contextInfo.
It usually is public data implicit from the context.  It is bound to the
resulting ciphertext, which allows for checking the integrity of contextInfo
(but there are no guarantees in regards to the secrecy or authenticity of
contextInfo).

#### Preparation

The recipient has to generate a private keyset and share the public keyset with
the sender.

**Warning**: DO NOT hardcode the private keyset in source code, consider
encrypting it using Cloud KMS or AWS KMS (see
[Key Management Systems](KEY-MANAGEMENT.md#key-management-systems)).

```go
package main

import (
        "fmt"
        "log"

        "github.com/golang/protobuf/proto"
        "github.com/google/tink/go/hybrid"
        "github.com/google/tink/go/insecurecleartextkeyset"
        "github.com/google/tink/go/keyset"
)

func main() {
        // Generate and persist private key.
        khPriv, err := keyset.NewHandle(hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate())
        if err != nil {
                log.Fatal(err)
        }

        exportedPriv := &keyset.MemReaderWriter{}
        if err := insecurecleartextkeyset.Write(khPriv, exportedPriv); err != nil {
          return nil, err
        }

        ksPriv, err := proto.Marshal(exported.Keyset)
        if err != nil {
          return nil, err
        }

        // TODO: store ksPriv somewhere safe.
        // DO NOT hardcode the private keyset in source code, consider
        // encrypting it with using Cloud KMS or AWS KMS.

        // Export and publish public keyset.
        khPub, err := khPriv.Public()
        if err != nil {
                log.Fatal(err)
        }

        exportedPub := &keyset.MemReaderWriter{}
        if err = insecurecleartextkeyset.Write(khPub, exportedPub); err != nil {
          return nil, err
        }

        ksPub, err := proto.Marshal(exported.Keyset)
        if err != nil {
          return nil, err
        }

        // TODO: share ksPub with the sender.
}
```

#### Encryption

After receiving a public keyset from the recipient, the sender can encrypt as
follows.

```go
package main

import (
        "fmt"
        "log"

        "github.com/google/tink/go/hybrid"
        "github.com/google/tink/go/insecurecleartextkeyset"
        "github.com/google/tink/go/keyset"
)

func main() {
        // TODO: obtain ksPub from the recipient (see the Preparation section).
        khPub, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(ksPub)))

        he, err := hybrid.NewHybridEncrypt(khPub)
        if err != nil {
                log.Fatal(err)
        }

        ct, err := he.Encrypt([]byte("secret message"), []byte("context info"))
        if err != nil {
                log.Fatal(err)
        }

        fmt.Printf("Cipher text: %s\n", ct)

}
```

#### Decryption

The recipient uses its private keyset to decrypt as follows.

**Warning**: DO NOT hardcode the private keyset in source code, consider
encrypting it using Cloud KMS or AWS KMS (see
[Key Management Systems](KEY-MANAGEMENT.md#key-management-systems)).

```go
package main

import (
        "fmt"
        "log"

        "github.com/google/tink/go/hybrid"
        "github.com/google/tink/go/insecurecleartextkeyset"
        "github.com/google/tink/go/keyset"
)

func main() {
        // TODO: load ksPriv from storage (see the Preparation section).
        // DO NOT hardcode the keyset in source code, consider encrypting it
        // with using Cloud KMS or AWS KMS.
        khPriv, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(ksPriv)))

        hd, err := hybrid.NewHybridDecrypt(khPriv)
        if err != nil {
                log.Fatal(err)
        }

        // TODO: receive the ct from the sender (see the Encryption section).
        pt, err := hd.Decrypt(ct, []byte("context info"))
        if err != nil {
                log.Fatal(err)
        }

        fmt.Printf("Plaintext text: %s\n", pt)

}
```

### Envelope encryption

Via the AEAD interface, Tink supports
[envelope encryption](KEY-MANAGEMENT.md#envelope-encryption).

For example, you can perform envelope encryption with a Google Cloud KMS key at
`gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar`
using the credentials in `credentials.json` as follows:

```go
package main

import (
        "fmt"

        "github.com/google/tink/go/aead"
        "github.com/google/tink/go/core/registry"
        "github.com/google/tink/go/integration/gcpkms"
        "github.com/google/tink/go/keyset"
)

const (
        keyURI          = "gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar"   // customize for your key
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

        ct, err := a.Encrypt([]byte("secret message"), []byte("associated data"))
        if err != nil {
                log.Fatal(err)
        }

        pt, err := a.Decrypt(ct, []byte("associated data"))
        if err != nil {
                log.Fatal(err)
        }

        fmt.Printf("Cipher text: %s\nPlain text: %s\n", ct, pt)

}
```

## Key management

### Generating new keys and keysets

To take advantage of key rotation and other key management features, you usually
do not work with single keys, but with keysets. Keysets are just sets of keys
with some additional parameters and metadata.

Internally Tink stores keysets as Protocol Buffers, but you can work with
keysets via a wrapper called keyset handle. You can generate a new keyset and
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

Key Template Type  | Key Template
------------------ | ------------
AEAD               | aead.AES128CTRHMACSHA256KeyTemplate()
AEAD               | aead.AES128GCMKeyTemplate()
AEAD               | aead.AES256CTRHMACSHA256KeyTemplate()
AEAD               | aead.AES256GCMKeyTemplate()
AEAD               | aead.ChaCha20Poly1305KeyTemplate()
AEAD               | aead.XChaCha20Poly1305KeyTemplate()
DAEAD              | daead.AESSIVKeyTemplate()
MAC                | mac.HMACSHA256Tag128KeyTemplate()
MAC                | mac.HMACSHA256Tag256KeyTemplate()
MAC                | mac.HMACSHA512Tag256KeyTemplate()
MAC                | mac.HMACSHA512Tag512KeyTemplate()
Signature          | signature.ECDSAP256KeyTemplate()
Signature          | signature.ECDSAP384KeyTemplate()
Signature          | signature.ECDSAP521KeyTemplate()
Hybrid             | hybrid.ECIESHKDFAES128GCMKeyTemplate()
Hybrid             | hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate()

To avoid accidental leakage of sensitive key material, one should avoid mixing
keyset generation and usage in code. To support the separation of these
activities Tink provides a command-line tool, [Tinkey](TINKEY.md), which can be
used for common key management tasks.

### Storing and loading existing keysets

After generating key material, you might want to persist it to a storage system.
Tink supports persisting the keys after encryption to any io.Writer and
io.Reader implementations.

```go
package main

import (
        "fmt"
        "log"

        "github.com/golang/protobuf/proto"
        "github.com/google/tink/go/aead"
        "github.com/google/tink/go/core/registry"
        "github.com/google/tink/go/integration/gcpkms"
        "github.com/google/tink/go/keyset"
)

const (
        keyURI          = "gcp-kms://..."
        credentialsPath = "/mysecurestorage/..."
)

func main() {

        // Generate a new key.
        kh1, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
        if err != nil {
                log.Fatal(err)
        }

        // Fetch the master key from a KMS.
        gcpClient := gcpkms.NewClientWithCredentials(keyURI, credentialsPath)

        registry.RegisterKMSClient(gcpClient)

        backend, err := gcpClient.GetAEAD(keyURI)
        if err != nil {
                log.Fatal(err)
        }

        masterKey, err = aead.NewKMSEnvelopeAEAD(*aead.AES256GCMKeyTemplate(), backend)
        if err != nil {
                log.Fatal(err)
        }

        // An io.Reader and io.Writer implementation which simply writes to memory.
        memKeyset := &keyset.MemReaderWriter{}

        // Write encrypts the keyset handle with the master key and writes to the
        // io.Writer implementation (memKeyset).  We recommend you encrypt the keyset
        // handle before persisting it.
        if err := kh1.Write(memKeyset, masterKey); err != nil {
                log.Fatal(err)
        }

        // Read reads the encrypted keyset handle back from the io.Reader implementation
        // and decrypts it using the master key.
        kh2, err := keyset.Read(memKeyset, masterKey)
        if err != nil {
                log.Fatal(err)
        }

        if !proto.Equal(kh1.Keyset(), kh2.Keyset()) {
                log.Fatal("key handlers are not equal")
        }

        fmt.Println("Key handlers are equal.")

}
```
