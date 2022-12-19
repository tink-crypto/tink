# Tink for TypeScript HOW-TO

This document presents instructions and TypeScript code snippets for common
tasks in [Tink](https://github.com/google/tink).

Depending on the specifics of your build setup, you may need to alter these
snippets to use a different import syntax. Both ES modules and UMD are
supported.

WARNING: Tink for TypeScript/JavaScript is still in an alpha state! Breaking
changes are likely.

## Setup instructions

To add Tink to a TypeScript/JavaScript project, just run:

```sh
npm install tink-crypto
```

Or, if you're using Yarn:

```sh
yarn add tink-crypto
```

## Generating new keys and keysets

To take advantage of key rotation and other key management features, you usually
do not work with single keys, but with keysets, which you can use via a wrapper
called `KeysetHandle`. Keysets are just sets of keys with some additional
parameters and metadata. You can generate a new keyset and obtain its handle
using a `KeyTemplate` (example in below code snippet).

To avoid accidental leakage of sensitive key material, you should usually avoid
mixing keyset generation and usage in code. To support the separation of these
activities Tink provides a command-line tool, [Tinkey](TINKEY.md), which can be
used for common key management tasks. Still, if there is a need to generate a
`KeysetHandle` with fresh key material directly in TypeScript code, you can use
`generateNewKeysetHandle`:

```javascript
import {aead, generateNewKeysetHandle} from 'tink-crypto';
const {aes256GcmKeyTemplate} = aead;

(async () => {
  const keyTemplate = aes256GcmKeyTemplate()
  const keysetHandle = await generateNewKeysetHandle(keyTemplate);
  // use the keyset...
})();
```

Currently, key templates are only available for AEAD encryption, digital
signatures, and hybrid encryption.

| Key       | Key Template                                                     |
: Template  :                                                                  :
: Type      :                                                                  :
| --------- | ---------------------------------------------------------------- |
| AEAD      | `aead.aes128GcmKeyTemplate()`                                    |
| AEAD      | `aead.aes256GcmKeyTemplate()`                                    |
| AEAD      | `aead.aes256GcmNoPrefixKeyTemplate()`                            |
| Signature | `signature.ecdsaP256KeyTemplate()`                               |
| Signature | `signature.ecdsaP256IeeeEncodingKeyTemplate()`                   |
| Signature | `signature.ecdsaP384KeyTemplate()`                               |
| Signature | `signature.ecdsaP384IeeeEncodingKeyTemplate()`                   |
| Signature | `signature.ecdsaP521KeyTemplate()`                               |
| Signature | `signature.ecdsaP521IeeeEncodingKeyTemplate()`                   |
| Hybrid    | `hybrid.eciesP256HkdfHmacSha256Aes128GcmKeyTemplate()`           |
| Hybrid    | `hybrid.eciesP256HkdfHmacSha256Aes128CtrHmacSha256KeyTemplate()` |

### Storing and loading existing keysets

After generating key material, you might want to persist it to LocalStorage or
IndexedDB, or send it to a server to be stored there. The `binary` and
`binaryInsecure` subpackages can be used to serialize and deserialize keysets to
and from `UInt8Array`. `binary` handles only public keys; `binaryInsecure` can
additionally handle private and symmetric keys. With these, you must be careful
not to leak the raw key material.

```javascript
import {aead, binaryInsecure, generateNewKeysetHandle} from 'tink-crypto';

const {Aead, register, aes256GcmKeyTemplate} = aead;
const {deserializeKeyset, serializeKeyset} = binaryInsecure;

register();

(async () => {
  const keysetHandle = await generateNewKeysetHandle(aes256GcmKeyTemplate());
  // Serialize keyset to send/store
  const serializedKeyset = serializeKeyset(keysetHandle);

  const deserializedKeyset = deserializeKeyset(serializedKeyset)
  const aead = await deserializedKeyset.getPrimitive(Aead);
  // Use deserialization... (i.e. to decrypt a ciphertext)
})();
```

## Obtaining and using primitives

[*Primitives*](PRIMITIVES.md) represent cryptographic operations offered by
Tink, hence they form the core of Tink API. A primitive is just an interface
that specifies what operations are offered by the primitive. A primitive can
have multiple implementations, and you choose a desired implementation by using
a key of corresponding type (see the
[this section](KEY-MANAGEMENT.md#key-keyset-and-keysethandle) for details).

A list of primitives and their implementations currently supported by Tink in
TypeScript/JavaScript can be found [here](PRIMITIVES.md#typescriptjavascript).
Note that there are currently a few additional limitations:

*   MAC is supported only via the subtle API, not the keyset API.
*   It's not possible to generate a fresh new asymmetric keyset using the keyset
    API and then use it without going through the subtle API. (The public key is
    not directly accessible yet)

### AEAD

AEAD encryption assures the confidentiality and authenticity of the data. This
primitive is CPA secure.

```javascript
// See live on StackBlitz: https://stackblitz.com/edit/tink-typescript?file=index.ts

import {aead, generateNewKeysetHandle} from 'tink-crypto';

const {Aead, register, aes256GcmKeyTemplate} = aead;

register();

(async () => {
  const keysetHandle = await generateNewKeysetHandle(aes256GcmKeyTemplate());
  const aead = await keysetHandle.getPrimitive(Aead);
  const ciphertext = await aead.encrypt(
      new TextEncoder().encode('this data needs to be encrypted'),
      new TextEncoder().encode('associated data'));
  const plaintext = new TextDecoder().decode(await aead.decrypt(
      ciphertext, new TextEncoder().encode('associated data')));
  console.log('Ciphertext:', ciphertext);
  console.log('Plaintext:', plaintext);
})();
```
