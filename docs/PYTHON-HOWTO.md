# Tink for Python HOW-TO

This document presents instructions and Python code snippets for common tasks in
[Tink](https://github.com/google/tink).

## Initializing Tink

Tink provides customizable initialization, which allows for choosing specific
implementations (identified by _key types_) of desired primitives. This
initialization happens via _registration_ of the implementations.

For example, if you want to use all standard implementations of all primitives
in the current release of Tink, the initialization would look as follows:

```python
import tink

tink.tink_config.register()
```

The registration of custom key managers can proceed directly via
the `Registry` class:

```python
import tink

tink.Registry.register_key_manager(CustomAeadKeyManager())
```

## Generating new keys and keysets

Each `KeyManager` implementation provides a `new_key_data(key_template)` method
that generates new keys of the corresponding key type.  However, to avoid
accidental leakage of sensitive key material you should avoid mixing key(set)
generation with key(set) usage in code.

To support the separation between these activities Tink package provides a
command-line tool called [Tinkey](TINKEY.md), which can be used for common key
management tasks.

Still, if there is a need to generate a KeysetHandle with fresh key material
directly in Python code, you can use `core.new_keyset_handle`:

```python
import tink

key_template = tink.aead.aead_key_templates.AES128_EAX
keyset_handle = tink.new_keyset_handle(key_template)
# use the keyset...
```

where `key_template` can be obtained from util classes corresponding to Tink
primitives, e.g.
[mac_key_templates](https://github.com/google/tink/blob/master/python/mac/mac_key_templates.py),
[aead_key_templates](https://github.com/google/tink/blob/master/python/aead/aead_key_templates.py),
or
[HybridKeyTemplates](https://github.com/google/tink/blob/master/python/hybrid/hybrid_key_templates.py).

## Loading existing keysets

To load cleartext keysets, use an appropriate [`KeysetReader`](https://github.com/google/tink/blob/master/python/core/keyset_reader.py),
depending on the wire format of the stored keyset, for example a
`BinaryKeysetReader` or a `JsonKeysetReader`.

```python
import tink

json_keyset = ...
reader = tink.JsonKeysetReader(json_keyset)
keyset = reader.read()
keyset_handle = tink.KeysetHandle(keyset)
```

To load encrypted keysets, one can use `core.read_keyset_handle` and an
appropriate [`KeysetReader`](https://github.com/google/tink/blob/master/python/core/keyset_reader.py):

```python
import tink

json_encrypted_keyset = ...
reader = tink.JsonKeysetReader(json_encrypted_keyset)
keyset_handle = tink.read_keyset_handle(reader, master_key_aead)
```
## Obtaining and using primitives

[_Primitives_](PRIMITIVES.md) represent cryptographic operations offered by
Tink, hence they form the core of the Tink API. A primitive is just an interface
that specifies what operations are offered by the primitive. A primitive can
have multiple implementations, and you choose a desired implementation by using
a key of corresponding type (see [this
section](KEY-MANAGEMENT.md#key-keyset-and-keysethandle) for further details).

Tink for Python supports the same primitives as Tink for C++. A list of
primitives and their implementations currently supported by Tink in C++ can be
found [here](PRIMITIVES.md#c).

You obtain a primitive by calling the method `primitive` of the `KeysetHandle`.

### Symmetric key encryption

You can obtain and use an [AEAD (Authenticated Encryption with Associated
Data)](PRIMITIVES.md#authenticated-encryption-with-associated-data) primitive to
encrypt or decrypt data:

```python
# 1. Get a handle to the key material.
keyset_handle = ...

# 2. Get the primitive.
aead = keyset_handle.primitive(tink.Aead)

# 3. Use the primitive.
ciphertext = aead.encrypt(plaintext, associated data)
```
