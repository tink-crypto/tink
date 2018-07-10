# Tink for Obj-C HOW-TO

The following subsections present instructions and/or Obj-C snippets for some
common tasks in [Tink](https://github.com/google/tink).

## Installing Tink

Tink is released as a [Cocoapod](https://cocoapods.org/). It can be installed by
using the pod command as described below.

#### Supported Platforms

 * iOS 9.0 or newer
 * Xcode 9.2 or newer

### Installing via Cocoapods

1. Change into the directory that contains your Xcode project.

   ```sh
   cd /path/to/your/Xcode project/
   ```

2. Initialize Cocoapods.

   ```sh
   pod init
   ```
   This command creates a file called Podfile.

3. Edit the Podfile.

   For a stable release, add the following line:

   ```
   pod 'Tink'
   ```

   For a pre-release use the following line instead:

   ```
   pod 'Tink', '1.2.0-rc1'
   ```

   Note: Replace 1.2.0-rc1 with the pre-release version you want to install.

4. Install the pod.

  ```sh
  $ pod install
  ```

5. Open the newly generated .xcworkspace and start using Tink.

   You can import the umbrella header:

   ```objc
   #import "Tink/Tink.h"
   ```

   Or individual headers:

   ```objc
   #import "Tink/TINKAeadConfig.h"
   #import "Tink/TINKAeadKeyTemplate.h"
   #import "Tink/TINKAead.h"
   ```

## Initializing Tink

Tink provides customizable initialization, which allows for choosing specific
implementations (identified by _key types_) of desired primitives. This
initialization happens via _registration_ of the implementations.

For example, if you want to use all implementations of all primitives in Tink
1.1.0, the initialization would look as follows:

```objc
   #import "Tink/TINKAllConfig.h"
   #import "Tink/TINKConfig.h"
   #import "Tink/TINKVersion.h"

   NSError *error = nil;
   TINKAllConfig *config = [[TINKAllConfig alloc] initWithVersion:TINKVersion1_1_0 error:&error];
   if (!config || error) {
     // handle error.
   }

   if (![TINKConfig registerConfig:config error:&error]) {
     // handle error.
   }
```

To use only implementations of the AEAD primitive:

```objc
    #import "Tink/TINKAeadConfig.h"
    #import "Tink/TINKConfig.h"
    #import "Tink/TINKVersion.h"

    NSError *error = nil;
    TINKAeadConfig *aeadConfig = [[TINKAeadConfig alloc] initWithVersion:TINKVersion1_1_0
                                                                   error:&error];
    if (!aeadConfig || error) {
      // handle error.
    }

    if (![TINKConfig registerConfig:aeadConfig error:&error]) {
      // handle error.
    }
```

## Generating New Key(set)s

To avoid accidental leakage of sensitive key material one should be careful
mixing keyset generation and usage in code. To support the separation
between these activities the Tink package provides a command-line tool called
[Tinkey](TINKEY.md), which can be used for common key management tasks.

Still, if there is a need to generate a KeysetHandle with fresh key material
directly in Obj-C code, one can use
[`TINKKeysetHandle`](https://github.com/google/tink/blob/master/objc/TINKKeysetHandle.h)
with one of the available KeyTemplates (AeadKeyTemplate, HybridKeyTemplate etc):

```objc
    #import "Tink/TINKAeadKeyTemplate.h"
    #import "Tink/TINKKeysetHandle.h"

    NSError *error = nil;
    TINKAeadKeyTemplate *tpl = [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes128Gcm error:&error];
    if (!tpl || error) {
      // handle error.
    }

    TINKKeysetHandle *handle = [[TINKKeysetHandle alloc] initWithKeyTemplate:tpl error:&error];
    if (!handle || error) {
      // handle error.
    }
```

## Loading Existing Keysets

To load cleartext keysets, use
[`TINKKeysetHandle+Cleartext`](https://github.com/google/tink/blob/master/objc/TINKKeysetHandle+Cleartext.h)
and an appropriate
[`KeysetReader`](https://github.com/google/tink/blob/master/objc/TINKKeysetReader.h),
depending on the wire format of the stored keyset, for example a
[`TINKBinaryKeysetReader`](https://github.com/google/tink/blob/master/objc/TINKBinaryKeysetReader.h).

```objc
    #import "Tink/TINKBinaryKeysetReader.h"
    #import "Tink/TINKKeysetHandle+Cleartext.h"

    NSError *error = nil;
    NSData *binaryKeyset = ...;
    TINKBinaryKeysetReader *reader = [[TINKBinaryKeysetReader alloc] initWithSerializedKeyset:binaryKeyset
                                                                                        error:&error];
    if (!reader || error) {
      // handle error.
    }

    TINKKeysetHandle *handle = [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:reader
                                                                                             error:&error];
    if (!handle || error) {
      // handle error.
    }
```

## Obtaining and Using Primitives

[_Primitives_](PRIMITIVES.md) represent cryptographic operations offered by
Tink, hence they form the core of Tink API. A primitive is just an interface
that specifies what operations are offered by the primitive. A primitive can
have multiple implementations, and user chooses a desired implementation by
using a key of corresponding type (see the [this
section](KEY-MANAGEMENT.md#key-keyset-and-keysethandle) for details).

The following table summarizes Obj-C implementations of primitives that are
currently available or planned (the latter are listed in brackets).

Primitive          | Implementations
------------------ | ---------------------------------
AEAD               | AES-GCM, AES-CTR-HMAC, AES-EAX
MAC                | HMAC-SHA2
Digital Signatures | ECDSA over NIST curves, (Ed25519)
Hybrid Encryption  | ECIES with AEAD and HKDF

Tink user accesses implementations of a primitive via a factory that corresponds
to the primitive: AEAD via `TINKAeadFactory`, MAC via `TINKMacFactory`, etc.
where each factory offers corresponding `primitiveWithKeysetHandle:error:`
methods.

### Symmetric Key Encryption

Here is how you can obtain and use an [AEAD (Authenticated Encryption with
Associated Data](PRIMITIVES.md#authenticated-encryption-with-associated-data)
primitive to encrypt or decrypt data:

```objc
    #import "Tink/TINKAead.h"
    #import "Tink/TINKKeysetHandle.h"
    #import "Tink/TINKAeadFactory.h"

    // 1. Get a handle to the key material.
    TINKKeysetHandle *keysetHandle = ...;

    // 2. Get the primitive.
    NSError *error = nil;
    id<TINKAead> aead = [TINKAeadFactory primitiveWithKeysetHandle:keysetHandle error:&error];
    if (!aead || error) {
      // handle error.
    }

    // 3. Use the primitive.
    NSData *ciphertext = [aead encrypt:plaintext withAdditionalData:aad error:&error];
    if (!ciphertext || error) {
      // handle error.
    }
```

### Hybrid Encryption

To decrypt using [a combination of public key encryption and symmetric key
encryption](PRIMITIVES.md#hybrid-encryption):

```objc
    #import "Tink/TINKHybridDecrypt.h"
    #import "Tink/TINKKeysetHandle.h"
    #import "Tink/TINKHybridDecryptFactory.h"

    // 1. Get a handle to the key material.
    TINKKeysetHandle *keysetHandle = ...;

    // 2. Get the primitive.
    NSError *error = nil;
    id<TINKHybridDecrypt> hybridDecrypt = [TINKHybridDecryptFactory primitiveWithKeysetHandle:keysetHandle
                                                                                        error:&error];
    if (!hybridDecrypt || error) {
      // handle error.
    }

    // 3. Use the primitive.
    NSData *plaintext = [hybridDecrypt decrypt:ciphertext withContextInfo:contextInfo error:&error];
    if (!plaintext || error) {
      // handle error.
    }
```
