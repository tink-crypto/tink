# Tink for C++ HOW-TO

The following subsections present instructions and/or C++ snippets for some
common tasks in [Tink](https://github.com/google/tink).

## Initializing Tink

Tink provides customizable initialization, which allows for choosing specific
implementations (identified by _key types_) of desired primitives. This
initialization happens via _registration_ of the implementations.  Registration

For example, if you want to use all implementations of all primitives in Tink
1.1.0, the initialization would look as follows:

```cpp
   #include cc/config/tink_config.h

   // ...
   auto status = TinkConfig::Init();
   if (!status.ok()) /* ... handle failure */;
   status = Config::Register(TinkConfig::Tink_1_1_0());
   // ...
```

To use only implementations of the AEAD primitive:

```cpp
   #include cc/aead/aead_config.h

   // ...
   auto status = AeadConfig::Init();
   if (!status.ok()) /* ... handle failure */;
   status = Config::Register(AeadConfig::Tink_1_1_0());
   // ...
```

For custom initialization the registration proceeds directly via
`Registry`-class:

```cpp
   #include cc/registry.h
   #include custom_project/custom_aead_key_manager.h

   // ...
   auto status = Registry::RegisterKeyManager(
       CustomAeadKeyManager.kKeyType, new CustomAeadKeyManager());
   if (!status.ok()) /* ... handle failure */;
```

## Generating New Key(set)s

Each `KeyManager`-implementation provides `NewKey(template)`-method that generates new
keys of the corresponding key type.  However to avoid accidental leakage of
sensitive key material one should be careful with mixing key(set) generation
with key(set) usage in code. To support the separation between these activities
Tink package provides a command-line tool called [Tinkey](TINKEY.md), which can
be used for common key management tasks.

Still, if there is a need to generate a KeysetHandle with fresh key material
directly in C++ code, one can use
[`KeysetHandle`](https://github.com/google/tink/blob/master/cc/keyset_handle.h):

```cpp
    auto new_keyset_result = KeysetHandle::GenerateNew(key_template);
    if (!new_keyset_result.ok()) return new_key_result.status();
    auto keyset = std::move(new_keyset_result.ValueOrDie());
    // use the keyset...
```

where `key_template` can be initialized with one of pre-generated templates from
[examples/keytemplates](https://github.com/google/tink/tree/master/examples/keytemplates)-folder.


## Loading Existing Keysets

To load cleartext keysets, use
[`CleartextKeysetHandle`](https://github.com/google/tink/blob/master/cc/cleartext_keyset_handle.h) and an appropriate [`KeysetReader`](https://github.com/google/tink/blob/master/cc/keyset_reader.h), depending on the wire format of the stored keyset, for example a [`BinaryKeysetReader`](https://github.com/google/tink/blob/master/cc/binary_keyset_reader.h) or a [`JsonKeysetReader`](https://github.com/google/tink/blob/master/cc/json_keyset_reader.h).

```cpp
    #include "cc/binary_keyset_reader.h"
    #include "cc/cleartext_keyset_handle.h"

    // ...
    std::string binary_keyset = ...;
    auto reader_result = BinaryKeysetReader::New(binary_keyset);
    if (!reader_result.ok()) return reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    auto handle_result = CleartextKeysetHandle::Read(std::move(reader));
    if (!handle_result.ok()) return handle_result.status();
    auto keyset_handle = std::move(handle_result.ValueOrDie());
```

To load encrypted keysets, one can use
[`KeysetHandle`](https://github.com/google/tink/blob/master/cc/keyset_handle.h) and an appropriate [`KeysetReader`](https://github.com/google/tink/blob/master/cc/keyset_reader.h):

```cpp
    #include "cc/aead.h"
    #include "cc/json_keyset_reader.h"
    #include "cc/cleartext_keyset_handle.h"
    #include "cc/integration/aws_kms_client.h"

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

## Obtaining and Using Primitives

[_Primitives_](PRIMITIVES.md) represent cryptographic operations offered by
Tink, hence they form the core of Tink API. A primitive is just an interface
that specifies what operations are offered by the primitive. A primitive can
have multiple implementations, and user chooses a desired implementation by
using a key of corresponding type (see the [this
section](KEY-MANAGEMENT.md#key-keyset-and-keysethandle) for details).

The following table summarizes C++ implementations of primitives that are
currently available or planned (the latter are listed in brackets).

| Primitive          | Implementations                               |
| ------------------ | --------------------------------------------- |
| AEAD               | AES-GCM, (AES-CTR-HMAC)                       |
| MAC                | HMAC-SHA2                                     |
| Digital Signatures | (ECDSA over NIST curves)                      |
| Hybrid Encryption  | ECIES with AEAD and HKDF                      |

Tink user accesses implementations of a primitive via a factory that corresponds
to the primitive: AEAD via `AeadFactory`, MAC via `MacFactory`, etc. where each
factory offers corresponding `getPrimitive(...)` methods.

### Symmetric Key Encryption

Here is how you can obtain and use an [AEAD (Authenticated Encryption with
Associated
Data](PRIMITIVES.md#authenticated-encryption-with-associated-data) primitive
to encrypt or decrypt data:

```cpp
    #include "cc/aead.h"
    #include "cc/keyset_handle.h"
    #include "cc/aead/aead_factory.h"


    // 1. Get a handle to the key material.
    KeysetHandle keyset_handle = ...;

    // 2. Get the primitive.
    auto aead_result= AeadFactory.GetPrimitive(keyset_handle);
    if (!aead_result.ok()) return aead_result.status();
    auto aead = std::move(aead_result.ValueOrDie());

    // 3. Use the primitive.
    auto ciphertext_result = aead.Encrypt(plaintext, aad);
    if (!ciphertext_result.ok()) return ciphertext.status();
    auto ciphertext = std::move(ciphertext_result.ValueOrDie());
```

### Hybrid Encryption

To decrypt using [a combination of public key encryption and
symmetric key encryption](PRIMITIVES.md#hybrid-encryption):

```cpp
    #include "cc/hybrid_decrypt.h"
    #include "cc/keyset_handle.h"
    #include "cc/hybrid/hybrid_decrypt_factory.h"


    // 1. Get a handle to the key material.
    KeysetHandle keyset_handle = ...;

    // 2. Get the primitive.
    auto hybrid_decrypt_result= HybridDecryptFactory.GetPrimitive(keyset_handle);
    if (!hybrid_decrypt_result.ok()) return hybrid_decrypt_result.status();
    auto hybrid_decrypt = std::move(hybrid_decrypt_result.ValueOrDie());

    // 3. Use the primitive.
    auto plaintext_result = hybrid_decrypt.Decrypt(ciphertext, context_info);
    if (!plaintext_result.ok()) return plaintext.status();
    auto plaintext = std::move(plaintext_result.ValueOrDie());
```

