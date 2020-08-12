# BoringSSL FIPS

This WORKSPACE facilitates building BoringSSL with the FIPS validated module
[BoringCrypto](https://csrc.nist.gov/Projects/Cryptographic-Module-Validation-Program/Certificate/3678),
which can then be used in Tink. Note that this gives no guarantee that you use
BoringSSL in a FIPS compliant manner when used. It is strongly recommended to read
the official
[security policy](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp3678.pdf)
for BoringCrypto.

To use the BoringCrypto module with Tink, you must update the Tink
[WORKSPACE file](https://github.com/google/tink/blob/master/cc/WORKSPACE)
to use the BoringSSL targets in this WORKSPACE. Tink then offers a
[FIPS-only mode](../../../docs/FIPS.md) which will restrict the usage to
algorithms which are FIPS approved *and* utilize the BoringCrypto module.
