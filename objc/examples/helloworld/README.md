# Obj-C Hello World

This is an example iOS application that can encrypt and decrypt text using
[AEAD (Authenticated Encryption with Associated Data)](../../../docs/PRIMITIVES.md#authenticated-encryption-with-associated-data).

It demonstrates the basic steps of using Tink, namely generating key material,
obtaining a primitive, and using the primitive to do crypto.

The example comes with a Podfile that demonstrates how to install Tink from
Cocoapods.

## Build and run

### Cocoapods

```shell
git clone https://github.com/google/tink
cd tink/objc/examples/helloworld
pod install
open TinkExampleApp.xcworkspace
```
