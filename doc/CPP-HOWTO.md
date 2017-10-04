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

