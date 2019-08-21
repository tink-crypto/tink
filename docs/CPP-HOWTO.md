# Tink for C++ HOW-TO

This document contains instructions and C++ code snippets for common tasks in
[Tink](https://github.com/google/tink).

## Setup instructions

### Bazel

Tink is built using [Bazel](https://www.bazel.build).

Using Tink in projects built with Bazel is straighforward and is the recommended
approach. For an example, see [this project which specifies Tink as a dependency
in a Bazel WORKSPACE file](https://github.com/thaidn/tink-examples).

#### Caveats

Tink has a number of library dependencies specified in the "cc" section of the
[Bazel WORKSPACE file](https://github.com/google/tink/blob/master/WORKSPACE).

Any project using Tink should either:

 * explicitly depend on the same versions of these libraries
 * not depend directly on these libraries at all (i.e. have only the indirect
   dependence via Tink).

### Precompiled library

There are projects where using Bazel is not an option. For such situations, we
offer a precompiled library that can be used with other build tools.

#### Supported platforms

*   Linux x86_64
*   macOS x86_64, 10.12.6 (Sierra) or newer

**Warning:** The use of Tink without Bazel is at experimental stage, so the
instructions given below might not work in some environments.

#### Using the precompiled library

1.  Download and extract the Tink library.

    ```sh
    OS="linux" # Change to "darwin" for macOS
    TARGET_DIR="/usr/local"

    curl -L \
    "https://storage.googleapis.com/tink/releases/libtink-${OS}-x86_64-1.2.0-rc2.tar.gz" \
    | sudo tar -xz -C ${TARGET_DIR}
    ```

    The tar command extracts the Tink library into the `lib` subdirectory of
    `TARGET_DIR`. For example, specifying `/usr/local` as `TARGET_DIR` causes tar to
    extract the Tink library into `/usr/local/lib`.

    If you'd prefer to extract the library into a different directory, adjust
    `TARGET_DIR` accordingly.

1.  On Linux, if you specified a system directory as the `TARGET_DIR` (for
    example, `/usr/local`), then run `ldconfig` to configure the linker.

    ```sh
    sudo ldconfig
    ```

    If you set `TARGET_DIR` to a non-system directory (for example, `~/mydir`),
    then you must append the extraction directory (for example, `~/mydir/lib`)
    to two environment variables:

    ```sh
    export LIBRARY_PATH=${LIBRARY_PATH}:${TARGET_DIR}/lib
    export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${TARGET_DIR}/lib
    ```

#### Compiling the library from source

#### Prerequisites

To install Tink from the source code, the following prerequisites must be installed:

 * [git](https://git-scm.com/) - to download the source of Tink
 * [Bazel](https://www.bazel.build) - to build the Tink library

**Note:** You need to use Bazel to build the library, but you will be able to
use the resultant build artifacts in a non-Bazel project.

#### Step-by-step instructions to build and use `libtink.so`

1.  Clone Tink from GitHub.

    ```sh
    git clone https://github.com/google/tink/
    ```

1.  Build the library and header file bundles.

    ```sh
    cd tink
    bazel build -c opt cc:libtink.so
    bazel build cc:tink_headers cc:tink_deps_headers
    ```

1.  Prepare the installation target directory.

    ```sh
    TARGET_DIR="/usr/local"
    mkdir -p ${TARGET_DIR}/lib ${TARGET_DIR}/include
    ```

1.  Install the libary and header file bundles.

    ```sh
    sudo cp bazel-bin/cc/libtink.so ${TARGET_DIR}/lib/
    sudo tar xfv bazel-genfiles/cc/tink_headers.tar -C ${TARGET_DIR}/include/
    sudo tar xfv bazel-genfiles/cc/tink_deps_headers.tar -C ${TARGET_DIR}/include/
    ```

1.  On Linux, if you specified a system directory as the `TARGET_DIR` (for
    example, `/usr/local`), then run `ldconfig` to configure the linker.

    ```sh
    sudo ldconfig
    ```

    If you set `TARGET_DIR` to a non-system directory (for example, `~/mydir`),
    then you must append the extraction directory (for example, `~/mydir/lib`)
    to two environment variables:

    ```sh
    export LIBRARY_PATH=${LIBRARY_PATH}:${TARGET_DIR}/lib
    export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${TARGET_DIR}/lib

    ```

### Validate your installation

To validate the installation, compile and run
[`hello_world.cc`](https://github.com/google/tink/tree/master/examples/helloworld/cc/hello_world.cc).

1. Download the source code and a test cryptographic key. Also, create some plaintext to encrypt.

   ```sh
   cd /tmp
   GITHUB_URL=https://raw.githubusercontent.com/google/tink/master/examples/helloworld/cc/
   curl ${GITHUB_URL}/hello_world.cc -O ${GITHUB_URL}/aes128_gcm_test_keyset_json.txt -O
   echo "some message to be encrypted" > plaintext.txt
   ```

1. Compile the source code.

   ```sh
   g++ -std=c++11 -I${TARGET_DIR}/include/ -L${TARGET_DIR}/lib/ hello_world.cc -ltink -o hello_world
   ```

1. Use the `hello_world` application to encrypt and decrypt the plaintext data.

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
   auto status = Registry::RegisterKeyManager(new CustomAeadKeyManager());
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
