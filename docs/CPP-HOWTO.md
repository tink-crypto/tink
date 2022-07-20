# Tink for C++ HOW-TO

This document contains instructions and C++ code snippets for common tasks in
[Tink](https://github.com/google/tink).

## Setup instructions

Tink can be built using [Bazel](https://www.bazel.build) or
[CMake](http://cmake.org). Using any other build system is currently not
supported. This implies that you need to build your binary from scratch.

### Bazel

Using Tink in projects built with Bazel is straightforward and is the recommended
approach. For reference, see [the C++
examples](https://github.com/google/tink/tree/master/examples/cc).

### CMake

Using Tink with CMake is supported, see [CMAKE-HOWTO](CMAKE-HOWTO.md) for a
detailed description.

## Initializing Tink

Tink provides customizable initialization, which allows for choosing specific
implementations (identified by _key types_) of desired primitives. This
initialization happens via _registration_ of the implementations.

For example, if you want to use all standard implementations of all primitives
in the current release of Tink, the initialization would be:

```cpp
   #include "tink/config/tink_config.h"

   // ...
   auto status = TinkConfig::Register();
   if (!status.ok()) /* ... handle failure */;
   // ...
```

To use standard implementations of only one primitive, say AEAD:

```cpp
   #include "tink/aead/aead_config.h"

   // ...
   auto status = AeadConfig::Register();
   if (!status.ok()) /* ... handle failure */;
   // ...
```

The registration of custom key managers can proceed directly via
`Registry` class:

```cpp
   #include "tink/registry.h"
   #include "custom_project/custom_aead_key_manager.h"

   // ...
   auto status =
       Registry::RegisterKeyManager(absl::make_unique<CustomAeadKeyManager>());
   if (!status.ok()) /* ... handle failure */;
```

## Generating new keys and keysets

Each `KeyManager` implementation provides a `NewKey(template)` method that
generates new keys of the corresponding key type.  However, to avoid accidental
leakage of sensitive key material, you should avoid mixing key(set) generation
with key(set) usage in code. To support the separation between these activities,
Tink provides a command-line tool called [Tinkey](TINKEY.md), which can be used
for common key management tasks.

Still, if there is a need to generate a KeysetHandle with fresh key material
directly in C++ code, you can use
[`KeysetHandle`](https://github.com/google/tink/blob/master/cc/keyset_handle.h):

```cpp
    auto new_keyset_handle_result = KeysetHandle::GenerateNew(key_template);
    if (!new_keyset_handle_result.ok()) return new_keyset_handle_result.status();
    auto keyset_handle = std::move(new_keyset_handle_result.ValueOrDie());
    // use the keyset...
```

Recommended key templates can be obtained from util classes corresponding to
Tink primitives, e.g.
[MacKeyTemplates](https://github.com/google/tink/blob/master/cc/mac/mac_key_templates.h),
[AeadKeyTemplates](https://github.com/google/tink/blob/master/cc/aead/aead_key_templates.h),
and
[HybridKeyTemplates](https://github.com/google/tink/blob/master/cc/hybrid/hybrid_key_templates.h).

## Loading existing keysets

To load encrypted keysets, use
[`KeysetHandle`](https://github.com/google/tink/blob/master/cc/keyset_handle.h)
and an appropriate
[`KeysetReader`](https://github.com/google/tink/blob/master/cc/keyset_reader.h)
depending on the wire format of the stored keyset, for example a
[`BinaryKeysetReader`](https://github.com/google/tink/blob/master/cc/binary_keyset_reader.h)
or a
[`JsonKeysetReader`](https://github.com/google/tink/blob/master/cc/json_keyset_reader.h):

```cpp
    #include "tink/aead.h"
    #include "tink/json_keyset_reader.h"
    #include "tink/cleartext_keyset_handle.h"
    #include "tink/integration/aws_kms_client.h"

    // ...
    std::string json_encrypted_keyset = ...;
    auto reader_result = JsonKeysetReader::New(json_encrypted_keyset);
    if (!reader_result.ok()) return reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    std::string master_key_uri =
        "aws-kms://arn:aws:kms:us-east-1:007084425826:key/84a65985-f868-4bfc-83c2-366618acf147";
    auto aead = std::move(AwsKmsClient::NewAead(master_key_uri).ValueOrDie());
    auto handle_result = KeysetHandle::Read(std::move(reader), *aead);
    if (!handle_result.ok()) return handle_result.status();
    auto keyset_handle = std::move(handle_result.ValueOrDie());
```

To load cleartext keysets, use
[`CleartextKeysetHandle`](https://github.com/google/tink/blob/master/cc/cleartext_keyset_handle.h)
and an appropriate
[`KeysetReader`](https://github.com/google/tink/blob/master/cc/keyset_reader.h),

```cpp
    #include "tink/binary_keyset_reader.h"
    #include "tink/cleartext_keyset_handle.h"

    // ...
    std::string binary_keyset = ...;
    auto reader_result = BinaryKeysetReader::New(binary_keyset);
    if (!reader_result.ok()) return reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    auto handle_result = CleartextKeysetHandle::Read(std::move(reader));
    if (!handle_result.ok()) return handle_result.status();
    auto keyset_handle = std::move(handle_result.ValueOrDie());
```

## Obtaining and using primitives

[_Primitives_](PRIMITIVES.md) represent cryptographic operations offered by
Tink, hence they form the core of the Tink API. A primitive is an interface that
specifies what operations are offered by the primitive. A primitive can have
multiple implementations, and you choose a desired implementation by using a key
of a corresponding type (see [this
document](KEY-MANAGEMENT.md#key-keyset-and-keysethandle) for further details).

A list of primitives and the implementations currently supported by Tink in C++
can be found [here](PRIMITIVES.md#c).

You obtain a primitive by calling the method `GetPrimitive<>` of a
`KeysetHandle`.

### Symmetric key encryption

You can use an [AEAD (Authenticated Encryption with Associated
Data)](PRIMITIVES.md#authenticated-encryption-with-associated-data) primitive to
encrypt or decrypt data:

```cpp
    #include "tink/aead.h"
    #include "tink/keyset_handle.h"


    // 1. Get a handle to the key material.
    KeysetHandle keyset_handle = ...;

    // 2. Get the primitive.
    auto aead_result= keyset_handle.GetPrimitive<Aead>();
    if (!aead_result.ok()) return aead_result.status();
    auto aead = std::move(aead_result.ValueOrDie());

    // 3. Use the primitive.
    auto ciphertext_result = aead.Encrypt(plaintext, aad);
    if (!ciphertext_result.ok()) return ciphertext_result.status();
    auto ciphertext = std::move(ciphertext_result.ValueOrDie());
```

### Hybrid encryption

You can encrypt and decrypt using [a combination of public key encryption and
symmetric key encryption](PRIMITIVES.md#hybrid-encryption):

```cpp
    #include "tink/hybrid_decrypt.h"
    #include "tink/keyset_handle.h"


    // 1. Get a handle to the key material.
    KeysetHandle keyset_handle = ...;

    // 2. Get the primitive.
    auto hybrid_decrypt_result = keyset_handle.GetPrimitive<HybridDecrypt>();
    if (!hybrid_decrypt_result.ok()) return hybrid_decrypt_result.status();
    auto hybrid_decrypt = std::move(hybrid_decrypt_result.ValueOrDie());

    // 3. Use the primitive.
    auto plaintext_result = hybrid_decrypt.Decrypt(ciphertext, context_info);
    if (!plaintext_result.ok()) return plaintext_result.status();
    auto plaintext = std::move(plaintext_result.ValueOrDie());
```

### Envelope encryption

Via the AEAD interface, Tink supports
[envelope encryption](KEY-MANAGEMENT.md#envelope-encryption).

For example, you can perform envelope encryption with a Google Cloud KMS key at
`gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar`
using the credentials in `credentials.json` as follows:

```cpp
  #include "tink/aead.h"
  #include "tink/aead_key_templates.h"
  #include "tink/keyset_handle.h"
  #include "tink/integration/gcpkms/gcp_kms_client.h"

  using crypto::tink::Aead;
  using crypto::tink::integration::gcpkms::GcpKmsClient;

  std::string kek_uri = "gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar";
  std::string credentials = "credentials.json";
  const KeyTemplate& dek_template = AeadKeyTemplates::Aes128Gcm();

  // Register GcpKmsClient.
  auto client_result = GcpKmsClient::RegisterNewClient(kek_uri, credentials);
  if (!client_result.ok()) {
    std::clog << "GCP KMS client registration failed: "
              << client_result.status().error_message()
              << "\n";
    exit(1);
  }


  // 1. Get a handle to the key material.
  const KeyTemplate& envelope_kt = AeadKeyTemplates::KmsEnvelopeAead(kek_uri, dek_template);
  auto new_keyset_handle_result = KeysetHandle::GenerateNew(envelope_kt);
  if (!new_keyset_handle_result.ok()) return new_keyset_handle_result.status();
  // The nice thing about envelope encryption is that you don't have to store
  // this keyset handle because it only contains a reference to the remote KEK.
  auto keyset_handle = std::move(new_keyset_handle_result.ValueOrDie());

  // 2. Get the primitive.
  auto aead_result= keyset_handle.GetPrimitive<Aead>();
  if (!aead_result.ok()) return aead_result.status();
  auto aead = std::move(aead_result.ValueOrDie());

  // 3. Use the primitive.
  auto ciphertext_result = aead->Encrypt(plaintext, aad);
  if (!ciphertext_result.ok()) return ciphertext_result.status();
  auto ciphertext = std::move(ciphertext_result.ValueOrDie());
```
