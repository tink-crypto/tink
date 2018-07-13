# Tink for Obj-C HOW-TO

The following subsections present instructions and/or Obj-C snippets for some
common tasks in [Tink](https://github.com/google/tink).

## Installing Tink

Tink is released as a [Cocoapod](https://cocoapods.org/). It can be installed by
using the pod command as described below.

We also provide step-by-step instructions on how to build and use Tink from
source. However, Cocoapods is the recommended way to use Tink.

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
   pod 'Tink', '1.2.0-rc2'
   ```

   Note: Replace 1.2.0-rc2 with the pre-release version you want to install.

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

### Installing from the source

#### Prerequisites

To install Tink from the source code, the following prerequisites must be
installed:

*   [git](https://git-scm.com/) - to download the source of Tink
*   [Bazel](https://www.bazel.build) v0.15.0 or newer - to build Tink

#### Step-by-step instructions

1.  Clone Tink from GitHub:

    ```sh
    git clone https://github.com/google/tink/
    ```

2.  Build the library and generate a static iOS framework:

    ```sh
    cd tink
    export XCODE_VERSION=9.2
    export IOS_SDK=11.2
    bazel build -c opt --ios_multi_cpus=i386,x86_64,armv7,arm64 --xcode_version="${XCODE_VERSION}" --ios_sdk_version="${IOS_SDK}" //objc:Tink_framework
    ```

    Adjust the following options according to your build environment:

    *   Set `XCODE_VERSION` to the Xcode version you are using to build your
        application.

    *   Set `IOS_SDK` to the version of the iOS SDK you are using in your
        application.

    *   The option `ios_multi_cpus` is used to generate a fat library that
        includes multiple architectures. Before submitting your application to
        the App Store you should generate a framework that includes only the ARM
        architectures and link it to your binary.

3.  Unzip Tink\_framework.zip into your Xcode project folder:

    ```sh
    unzip bazel-bin/objc/Tink_framework.zip -d /path/to/your/project/folder/
    ```

4.  Add the static framework to your Xcode project options:

    *   Open your Xcode project

    *   Navigate to your project's folder and drag Tink.framework into your
        Xcode's left pane.

    *   In the following dialog select `Copy items if needed` and the target of
        your application that will use Tink. Click `Finish`.

    *   Select your project on the left pane and click on "Build Settings"

    *   Find `Other Linker Flags` and add `-lc++`

5.  Start using Tink in your code:

    Add `#import "Tink/Tink.h"` in your code and start using
    Tink.

## Initializing Tink

Tink provides customizable initialization, which allows for choosing specific
implementations (identified by _key types_) of desired primitives. This
initialization happens via _registration_ of the implementations.

For example, if you want to use all implementations of all primitives in the
current version of Tink, the initialization would look as follows:

```objc
   #import "Tink/TINKAllConfig.h"
   #import "Tink/TINKConfig.h"

   NSError *error = nil;
   TINKAllConfig *config = [[TINKAllConfig alloc] initWithError:&error];
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

    NSError *error = nil;
    TINKAeadConfig *aeadConfig = [[TINKAeadConfig alloc] initWithError:&error];
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

## Storing Keysets

After generating key material, you might want to persist it to a storage system.
Tink supports storing keysets to the iOS keychain where they remain encrypted:

```objc
    #import "Tink/TINKKeysetHandle.h"

    NSError *error = nil;
    TINKKeysetHandle *handle = [[TINKKeysetHandle alloc] initWithKeyTemplate:tpl error:&error];
    if (!handle || error) {
      // handle error.
    }

    NSString *keysetName = @"com.yourcompany.yourapp.uniqueKeysetName";
    if (![handle writeToKeychainWithName:keysetName overwrite:NO error:&error]) {
      // handle error.
    }
```

The keysets are stored in the keychain with the following options set:

*   kSecAttrAccessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
*   kSecAttrSynchronizable = False

These settings prevent the keysets from leaving the device and keep them
encrypted until the device is unlocked once.

## Loading Existing Keysets

To load keysets from the iOS keychain:

```objc
    #import "Tink/TINKKeysetHandle.h"

    NSError *error = nil;
    NSString *keysetName = @"com.yourcompany.yourapp.uniqueKeysetName";
    TINKKeysetHandle *handle = [[TINKKeysetHandle alloc] initFromKeychainWithName:keysetName error:&error];
    if (!handle || error) {
      // handle error.
    }
```

To load cleartext keysets, use
[`TINKKeysetHandle+Cleartext`](https://github.com/google/tink/blob/master/objc/TINKKeysetHandle+Cleartext.h)
and an appropriate
[`KeysetReader`](https://github.com/google/tink/blob/master/objc/TINKKeysetReader.h),
depending on the wire format of the stored keyset, for example a
[`TINKBinaryKeysetReader`](https://github.com/google/tink/blob/master/objc/TINKBinaryKeysetReader.h).

Note: We don't recommend storing keysets in cleartext in the filesystem.
Instead, use the iOS keychain as demonstrated above.

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
