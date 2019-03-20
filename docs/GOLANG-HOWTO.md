# HOW-TO Guide for Tink in Golang

The following subsections present instructions and/or Golang snippets for
accomplishing some common cryptographic tasks using [Tink](https://github.com/google/tink).

## Installing Tink

To install Tink locally run

```sh
go get github.com/google/tink/go/...
```

to run all the tests locally

```sh
cd $GOPATH/go/src/github.com/google/tink/go
go test ./...
```

Golang Tink API also supports [Bazel](https://www.bazel.build) builds. To run the tests using bazel

```sh
cd $GOPATH/go/src/github.com/google/tink/go
bazel build ... && bazel test ...
```

## GoDoc

GoDocs for the Tink API can be found [here](https://godoc.org/github.com/google/tink).

## Obtaining and Using Primitives

[_Primitives_](PRIMITIVES.md) represent cryptographic operations offered by
Tink, hence they form the core of Tink API. A primitive is just an interface
that specifies what operations are offered by the primitive. A primitive can
have multiple implementations, and user chooses a desired implementation by
using a key of corresponding type (see the [this
section](KEY-MANAGEMENT.md#key-keyset-and-keysethandle) for details).

The following table summarizes Golang implementations of primitives that are
currently available

Primitive          | Implementations
------------------ | ---------------------------------
AEAD               | AES-GCM, AES-CTR-HMAC
Deterministic AEAD | AES-SIV
MAC                | HMAC-SHA256
Digital Signatures | ECDSA over NIST curves, Ed25519
Hybrid Encryption  | ECIES with AEAD and HKDF

### AEAD

AEAD encryption assures the confidentiality and authenticity of the data. This primitive is CPA secure.

```go
package main

import (
    "fmt"

    "github.com/google/tink/go/aead"
    "github.com/google/tink/go/keyset"
)

func main() {

    kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
    if err != nil {
        // handle the error
    }

    a := aead.New(kh)

    ct , err := a.Encrypt([]byte("this data needs to be encrypted"), []byte("associated data"))
    if err != nil {
        // handle error
    }

    pt, err := a.Decrypt(ct, []byte("associated data"))
    if err != nil {
        //handle error
    }

}

```

### MAC

MAC computes a tag for a given message that can be used to authenticate a message. MAC protects data integrity as well as provides for authenticity of the message.

```go
package main

import (
    "fmt"

    "github.com/google/tink/go/mac"
    "github.com/google/tink/go/keyset"
)

func main() {

    kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
    if err != nil {
        // handle the error
    }

    m := mac.New(kh)

    mac , err := m.ComputeMac([]byte("this data needs to be MACed"))
    if err != nil {
        // handle error
    }

    if m.VerifyMAC(mac, []byte("this data needs to be MACed")); err != nil {
        //handle error
    }

}
```

### Deterministic AEAD

Unlike AEAD, implementations of this interface are not semantically secure, because
encrypting the same plaintex always yields the same ciphertext.

```go
package main

import (
    "fmt"

    "github.com/google/tink/go/daead"
    "github.com/google/tink/go/keyset"
)

func main() {

    kh, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
    if err != nil {
        // handle the error
    }

    d := daead.New(kh)

    ct1 , err := d.EncryptDeterministically([]byte("this data needs to be encrypted"), []byte("additional data"))
    if err != nil {
        // handle error
    }

    pt , err := d.DecryptDeterministically(ct, []byte("additional data"))
    if err != nil {
        // handle error
    }

    ct2 , err := d.EncryptDeterministically([]byte("this data needs to be encrypted"), []byte("additional data"))
    if err != nil {
        // handle error
    }

    // ct1 will be equal to ct2


}
```

### Signature

To sign data using Tink you can use ECDSA or ED25519 key templates.

```go
package main

import (
    "fmt"

    "github.com/google/tink/go/signature"
    "github.com/google/tink/go/keyset"
)

func main() {

    kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate()) // other key templates can also be used
    if err != nil {
        // handle the error
    }

    s := signature.NewSigner(kh)

    a , err := s.Sign([]byte("this data needs to be signed"))
    if err != nil {
        // handle error
    }

    v := signature.NewVerifier(kh)

    if err := v.Verify(a, []byte("this data needs to be signed")); err != nil {
        // handle error
    }


}
```

### Hybrid Encryption and Decryption

The functionality of Hybrid Encryption is represented as a pair of primitives (interfaces):
HybridEncrypt for encryption of data, and HybridDecrypt for decryption.
Implementations of these interfaces are secure against adaptive chosen ciphertext attacks. In
addition to plaintext the encryption takes an extra parameter contextInfo, which
usually is public data implicit from the context, but should be bound to the resulting
ciphertext, i.e. the ciphertext allows for checking the integrity of contextInfo (but
there are no guarantees wrt. the secrecy or authenticity of contextInfo).

```go
package main

import (
    "github.com/google/tink/go/hybrid"
    "github.com/google/tink/go/core/registry"
    "github.com/google/tink/go/keyset"
)


func main() {

    kh , err := keyset.NewHandle(hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate())
    if err != nil {
        //handle error
    }
    h := hybrid.NewHybridEncrypt(kh)

    ct, err = h.Encrypt([]byte("secret message"), []byte("context info"))
    if err != nil {
        // handle error
    }

    khd , err := keyset.NewHandle( .....); /// get a handle on the decryption key material
    hd := hybrid.NewHybridDecrypt(khd)

    pt, err := hd.Decrypt(ct, []byte("context info"))
    if err != nil {
        // handle error
    }
}

```


### Envelope Encryption

Tink APIs work with GCP and AWS KMS.

```go
package main

import (
    "github.com/google/tink/go/aead"
    "github.com/google/tink/go/core/registry"
    "github.com/google/tink/go/integration/gcpkms"
    "github.com/google/tink/go/keyset"
)

const (
    keyURI = "gcp-kms://......"
)

func main() {
    gcpclient := gcpkms.NewGCPClient(keyURI)
    _, err := gcpclient.LoadCredentials("/mysecurestorage/credentials.json")
    if err != nil {
        //handle error
    }
    registry.RegisterKMSClient(gcpclient)

    dek := aead.AES128CTRHMACSHA256KeyTemplate()
    kh, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(keyURI, dek))
    if err != nil {
        // handle error
    }
    a, err := aead.New(kh)
    if err != nil {
        // handle error
    }

    ct, err = a.Encrypt([]byte("secret message"), []byte("associated data"))
    if err != nil {
        // handle error
    }

    pt, err = a.Decrypt(ct, []byte("associated data"))
    if err != nil {
        // handle error
    }
}

```

## Key Management

### Generating New Key(set)s
To take advantage of key rotation and other key management features, a Tink user works usually not
with single keys, but with keysets, which are just sets of keys with some additional parameters and metadata.

Internally Tink stores keysets as Protocol Buffers, but you can work with keysets via a wrapper called keyset handle. You can generate a new keyset and obtain its handle using a KeyTemplate. KeysetHandle objects enforce certain restrictions that prevent accidental leakage of the sensistive key material.


```go
package main

import (
    "fmt"

    "github.com/google/tink/go/aead"
    "github.com/google/tink/go/keyset"
)

func main() {

    kh, err := keyset.NewHandle(aead.AES128GCMKeyTemplate()) // other key templates can also be used
    if err != nil {
        // handle the error
    }
    fmt.Println(kh.String())
}

```

Key templates are available for MAC, digital signatures and AEAD encryption.

Key Template Type  | Key Template
------------------ | ------------
AEAD               | aead.AES128CTRHMACSHA256KeyTemplate()
AEAD               | aead.AES128GCMKeyTemplate()
AEAD               | aead.AES256CTRHMACSHA256KeyTemplate()
AEAD               | aead.AES256GCMKeyTemplate()
MAC                | mac.HMACSHA256Tag128KeyTemplate()
MAC                | mac.HMACSHA256Tag256KeyTemplate()
Signature          | signature.ECDSAP256KeyTemplate()
Signature          | signature.ECDSAP384KeyTemplate()
Signature          | signature.ECDSAP521KeyTemplate()

To avoid accidental leakage of sensitive key material one should be careful
mixing keyset generation and usage in code. To support the separation
between these activities the Tink provides a command-line tool called
[Tinkey](TINKEY.md), which can be used for common key management tasks.

### Storing and Loading existing Keysets

After generating key material, you might want to persist it to a storage system.
Tink supports persisting the keys after encryption to any io.Writer and io.Reader
implementations.

```go
package main

import (
    "github.com/golang/protobuf/proto"
    "github.com/google/tink/go/aead"
    "github.com/google/tink/go/keyset"
)

func main() {

    kh, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
    if err != nil {
        // handle error
    }

    // Fetch the master key
    masterKey = aead.NewKMSEnvelopeAead("..", "..") //key template, //remote aead
    if err != nil {
        // handle error
    }

    // io.Reader and io.Writer implementation. This is simply writing to memory.
    memKeyset := &keyset.MemReaderWriter{}

    // Write encrypts the keyset handle with the master key and
    // writes to the io.Writer implementation(memKeyset)
    // We recommend you encrypt the keyset handle before persisting.
    if err := kh.Write(memKeyset, masterKey); err != nil {
        // handle error
    }

    // Read reads the encrypted keyset handle back from the io.Reader implementation
    // and decrypts it using the master key.
    kh2, err := keyset.Read(memKeyset, masterKey)
    if err != nil {
        // handle error
    }

    if !proto.Equal(kh.Keyset(), kh2.Keyset()) {
        // handle error
    }
}
```


