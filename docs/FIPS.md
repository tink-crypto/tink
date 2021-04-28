# Tink - FIPS 140-2

Currently, Tink is not
[FIPS 140-2](https://csrc.nist.gov/publications/detail/fips/140/2/final)
validated itself. However, it supports several FIPS 140-2 approved algorithms and the
underlying implementations *can* utilize validated cryptographic modules like
[BoringSSLs BoringCrypto](https://csrc.nist.gov/Projects/Cryptographic-Module-Validation-Program/Certificate/3678).
Tink includes a
[WORKSPACE](https://github.com/google/tink/blob/master/cc/third_party/boringssl_fips)
for building BoringSSL in FIPS mode.

## Algorithms supported

The following algorithms in Tink are approved according to
[FIPS 140-2](https://csrc.nist.gov/publications/detail/fips/140/2/final)

*   Authenticated Encryption
    *   AES-GCM ([FIPS 140-2 Annex A][fips_140_2_annex_a])
    *   AES-CTR-HMAC-SHA256 ([FIPS 140-2 Annex A][fips_140_2_annex_a])
*   MAC
    *   HMAC-SHA256 ([FIPS 140-2 Annex A][fips_140_2_annex_a])
    *   AES-CMAC ([FIPS 140-2 Annex A][fips_140_2_annex_a])
*   Digital Signatures
    *   ECDSA ([FIPS 140-2 Annex A][fips_140_2_annex_a])
    *   RSA-SSA-PKCS1 ([FIPS 140-2 Annex A][fips_140_2_annex_a])
    *   RSA-SSA-PSS ([FIPS 140-2 Annex A][fips_140_2_annex_a])

[fips_140_2_annex_a]: https://csrc.nist.gov/CSRC/media/Publications/fips/140/2/final/documents/fips1402annexa.pdf

## FIPS-only mode

If you are required to use FIPS 140-2 approved algorithms and validated
implementations, then you can build Tink in FIPS-only mode. This will restrict
usage to approved algorithms *and* check if Tink is utilizing a validated
cryptographic module.

Specifically this will change the behavior of Tink in the following way:

*   `Register()` functions will only register algorithms which have a FIPS
    validated implementation. This means that you will *only* be able to use
    Keysets for algorithms which use a validated cryptographic module.
*   Tink will check if BoringSSL has been built with the BoringCrypto module.
    Calls to primitives will return an `INTERNAL` error when the module is not
    available.
*   Using primitives in `subtle/` will be restricted to algorithms which utilize
    a validated cryptographic module.

Currently this is only supported in the C++ version of Tink.

### BoringCrypto

Tink uses
[BoringCrypto](https://csrc.nist.gov/Projects/Cryptographic-Module-Validation-Program/Certificate/3678)
in C++ to provide access to a validated cryptographic module. It's current
validation status imposes the following additional constraints on available
algorithms when in FIPS-only mode:

*   AES-CMAC has not been validated and is not available
*   RSA-SSA-PKCS1 is restricted to 3072-bit modulus
*   RSA-SSA-PSS is restricted to 3072-bit modulus

To use the BoringCrypto module via Bazel, you can uncomment the `local_repository`
definition for `boringssl` in the [C++
WORKSPACE](https://github.com/google/tink/blob/master/cc/WORKSPACE).

### Enabling at compile time

To build Tink in FIPS-only mode, you simply set a flag at compile time:

```shell
bazel build ... --//third_party/tink/cc/config:use_only_fips=True
```

If you want to check at runtime whether Tink has been build in FIPS only mode,
you can include the header `internal/fips_utils.h` which provides the constant
`kUseOnlyFips`.

If you are *not* building Tink in FIPS only mode, it will still utilize
validated implementations for *some* algorithms but not restrict the usage of
other algorithms.

### Enabling at run time

Alternatively to building Tink in FIPS-only  mode, you can call
`crypto::tink::RestrictToFips()` from `config/tink_fips.h` which will set a flag
at runtime to enable the restrictions to FIPS primitives.

WARNING: If you use the runtime option, then `crypto::tink::RestrictToFips()`
must be called before handling any key material, registering key manager or
other Tink functionalities. You further have to ensure that BoringSSL has been
built with the BoringCrypto module, as otherwise Tink will not allow you to
process any data.
