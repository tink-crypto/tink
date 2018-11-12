# Tink for C++ HOW-TO

The following subsections present instructions and/or C++ snippets for some
common tasks in [Tink](https://github.com/google/tink).


## Installing Tink

Tink is built with [Bazel](https://www.bazel.build), so it is quite easy to use
Tink in a project built with Bazel, and this is the recommended way.  See for
example [tink-examples repo](https://github.com/thaidn/tink-examples) on how to
import Tink using Bazel's WORKSPACE file.

Still, there are definitely projects for which using Bazel is not an option, and
for such situations we offer a library that can be used with other build
tools.  Currently only we offer support for Linux machines, but are working on
supporting other operating systems as well.

**Warning:** In any case, the use of Tink without Bazel is at experimental stage,
so the instructions given below might not work in some environments.

#### Supported Platforms

*   Linux x86_64
*   macOS x86_64, 10.12.6 (Sierra) or newer

#### Caveats

Tink depends on [Abseil](https://github.com/abseil/abseil-cpp), [Protocol
Buffers](https://developers.google.com/protocol-buffers/), and
[BoringSSL](https://opensource.google.com/projects/boringssl), so any project
that wants to use Tink should either depend on the same versions of these
libraries (cf. versions in the corresponding entries in
[WORKSPACE](https://github.com/google/tink/blob/master/WORKSPACE) file), or not
depend directly on these libraries at all (i.e. have only the indirect
dependence via Tink).

### Installing pre-built binaries

1.  Download and extract the Tink library into `/usr/local/lib` by invoking the
    following shell commands:

    ```sh
    OS="linux" # Change to "darwin" for macOS
    TARGET_DIR="/usr/local"
    curl -L \
    "https://storage.googleapis.com/tink/releases/libtink-${OS}-x86_64-1.2.0-rc2.tar.gz" |
    sudo tar -xz -C $TARGET_DIR
    ```

The tar command extracts the Tink library into the `lib` subdirectory of
`TARGET_DIR`. For example, specifying `/usr/local` as `TARGET_DIR` causes tar to
extract the Tink library into `/usr/local/lib`.

If you'd prefer to extract the library into a different directory, adjust
`TARGET_DIR` accordingly.

1.  On Linux, if in Step 2 you specified a system directory (for example,
    `/usr/local`) as the `TARGET_DIR`, then run ldconfig to configure the
    linker. For example:

    ```sh
    sudo ldconfig
    ```

    If you assigned a `TARGET_DIR` other than a system directory (for example,
    `~/mydir`), then you must append the extraction directory (for example,
    `~/mydir/lib`) to two environment variables:

    ```sh
    export LIBRARY_PATH=$LIBRARY_PATH:$TARGET_DIR/lib
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$TARGET_DIR/lib
    ```

### Installing from the source

#### Prerequisites

To install Tink from the source code, the following prerequisites must be installed:

 * [git](https://git-scm.com/) - to download the source of Tink
 * [Bazel](https://www.bazel.build) - to build the Tink library

#### Step-by-step instructions to build and use `libtink.so`

1.  clone Tink from GitHub:

    ```sh
    git clone https://github.com/google/tink/
    ```

2.  build the library and header-file bundles, and install them in appropriate
    directories of the target project (`TARGET_DIR`):

    ```sh
    cd tink
    TARGET_DIR="/usr/local"
    bazel build -c opt cc:libtink.so
    bazel build cc:tink_headers cc:tink_deps_headers
    mkdir -p $TARGET_DIR/lib $TARGET_DIR/include
    sudo cp bazel-bin/cc/libtink.so $TARGET_DIR/lib/
    sudo tar xfv bazel-genfiles/cc/tink_headers.tar -C $TARGET_DIR/include/
    sudo tar xfv bazel-genfiles/cc/tink_deps_headers.tar -C $TARGET_DIR/include/
    ```

3.  On Linux, if in Step 2 you specified a system directory (for example,
    `/usr/local`) as the `TARGET_DIR`, then run ldconfig to configure the
    linker. For example:

    ```sh
    sudo ldconfig
    ```

    If you assigned a `TARGET_DIR` other than a system directory (for example,
    `~/mydir`), then you must append the extraction directory (for example,
    `~/mydir/lib`) to two environment variables:

    ```sh
    export LIBRARY_PATH=$LIBRARY_PATH:$TARGET_DIR/lib
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$TARGET_DIR/lib
    ```

### Validate your installation

To validate the installation compile and run [`hello_world.cc`](https://github.com/google/tink/tree/master/examples/helloworld/cc/hello_world.cc).

1. Copy the source code and a test cryptographic key, create some plaintext to encrypt.

   ```sh
   cd /tmp
   GITHUB_DIR=https://raw.githubusercontent.com/google/tink/master/examples/helloworld/cc/
   curl $GITHUB_DIR/hello_world.cc -O $GITHUB_DIR/aes128_gcm_test_keyset_json.txt -O
   echo "some message to be encrypted" > plaintext.txt
   ```

2. Compile the source code.

   ```sh
    g++ -std=c++11 -I$TARGET_DIR/include/ -L$TARGET_DIR/lib/ hello_world.cc -ltink -o hello_world
   ```

3. Run `hello_world` application to encrypt and decrypt some data.

   ```sh
   ./hello_world aes128_gcm_test_keyset_json.txt encrypt plaintext.txt "associated data" ciphertext.bin
   ./hello_world aes128_gcm_test_keyset_json.txt decrypt ciphertext.bin "associated data" decrypted.txt
   cat decrypted.txt
   ```

## Initializing Tink

Tink provides customizable initialization, which allows for choosing specific
implementations (identified by _key types_) of desired primitives. This
initialization happens via _registration_ of the implementations.

For example, if you want to use all standard implementations of all primitives
in the current release of Tink, the initialization would look as follows:

```cpp
   #include "tink/config/tink_config.h"

   // ...
   auto status = TinkConfig::Register();
   if (!status.ok()) /* ... handle failure */;
   // ...
```

To use standard implementations of only one primitive, say AEAD, proceed as follows:

```cpp
   #include "tink/aead/aead_config.h"

   // ...
   auto status = AeadConfig::Register();
   if (!status.ok()) /* ... handle failure */;
   // ...
```

The registration of custom key managers can proceed directly via
`Registry`-class:

```cpp
   #include "tink/registry.h"
   #include "custom_project/custom_aead_key_manager.h"

   // ...
   auto status = Registry::RegisterKeyManager(new CustomAeadKeyManager());
   if (!status.ok()) /* ... handle failure */;
```

A more complex custom initialization (especially when registering a mix of
standard and custom key managers) can take advantage of
[`Config`](https://github.com/google/tink/blob/master/cc/config.h)-class, which
enables use of human-readable configuration files for Tink initialization.
Please note however that to use such configurations one must first add to the
Registry so-called _catalogues_, which provide a bridge between text
descriptions of key managers and their implementations (see
e.g. [`AeadConfig::Register()`](https://github.com/google/tink/blob/master/cc/aead/aead_config.cc)-method).


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
    auto new_keyset_handle_result = KeysetHandle::GenerateNew(key_template);
    if (!new_keyset_handle_result.ok()) return new_keyset_handle_result.status();
    auto keyset_handle = std::move(new_keyset_handle_result.ValueOrDie());
    // use the keyset...
```

where `key_template` can be initialized with one of pre-generated templates from
[examples/keytemplates](https://github.com/google/tink/tree/master/examples/keytemplates)-folder.


## Loading Existing Keysets

To load cleartext keysets, use
[`CleartextKeysetHandle`](https://github.com/google/tink/blob/master/cc/cleartext_keyset_handle.h) and an appropriate [`KeysetReader`](https://github.com/google/tink/blob/master/cc/keyset_reader.h), depending on the wire format of the stored keyset, for example a [`BinaryKeysetReader`](https://github.com/google/tink/blob/master/cc/binary_keyset_reader.h) or a [`JsonKeysetReader`](https://github.com/google/tink/blob/master/cc/json_keyset_reader.h).

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

To load encrypted keysets, one can use
[`KeysetHandle`](https://github.com/google/tink/blob/master/cc/keyset_handle.h) and an appropriate [`KeysetReader`](https://github.com/google/tink/blob/master/cc/keyset_reader.h):

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
| AEAD               | AES-GCM, AES-CTR-HMAC, AES-EAX                |
| Deterministic AEAD | AES-SIV                                       |
| MAC                | HMAC-SHA2                                     |
| Digital Signatures | ECDSA over NIST curves, (Ed25519)             |
| Hybrid Encryption  | ECIES with AEAD and HKDF                      |

The user obtains a primitive by calling the function `getPrimitive<>` of the
`KeysetHandle`.

### Symmetric Key Encryption

Here is how you can obtain and use an [AEAD (Authenticated Encryption with
Associated
Data)](PRIMITIVES.md#authenticated-encryption-with-associated-data) primitive
to encrypt or decrypt data:

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

### Hybrid Encryption

To decrypt using [a combination of public key encryption and
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
