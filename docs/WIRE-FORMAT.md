# Tink Wire Format

<!--*
# Document freshness: For more information, see go/fresh-source.
freshness: { owner: 'sschmieg' reviewed: '2021-02-18' }
*-->

This is a description of Tink's wire format for keys and primitive output. The
documentation is aimed at cryptographers wanting to add additional languages to
Tink and maintainers of other high-level crypto libraries wanting to give a wire
compatible mode. It is not intended for general audiences.

## Keys

Tink uses Google protobuf to store its keys. A keyset contains a serialized
proto of the corresponding type as its KeyData value property. An encrypted
keyset similarly is the wire format of the proto library, encrypted with the
given AEAD, stored in the corresponding proto.

## Crypto Formats

By default, primitives use the Tink prefix output mode. This mode results in a
five byte prefix consisting of:

*   1 byte version (0x01 for Tink, 0x00 for Google internal legacy formats)
*   4 bytes key hint. This is the key id to be used to try to decrypt/verify
    this ciphertext first.

Note that this prefix is not authenticated and cannot be relied on for security
purposes. Tink will first try and decrypt/validate a ciphertext with the hinted
key and if the operation fails, it will proceed to attempt to decrypt/validate
with all keys that have RAW prefix type specified.

### AEAD

In general, Tink will format AEAD ciphertexts as

```
IV || ciphertext || tag,
```

unless otherwise specified in the corresponding RFC.

#### AES-CTR-HMAC

For AES-CTR-HMAC, Tink will compute the MAC with associated data as follows:

```
AAD || IV || ciphertext || bitlen(AAD)
```

with bitlen(AAD) is aad's length in bits represented as 64-bit bigendian
unsigned integer. This HMAC scheme follows the draft for AES-CBC-HMAC from
[Mcgrew](https://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05).

### Deterministic AEAD

Tink implements RFC 5297 for AES-SIV, putting the SIV/Tag at the beginning of
the ciphertext.

### Streaming Encryption

The format of the ciphertext is

```
header || segment_0 || segment_1 || ... || segment_k
```

where:

*   `segment_i` is the `i`-th segment of the ciphertext.
*   the size of `segment_1` .. `segment_{k-1}` is
    `get_ciphertext_segment_size()`
*   `segment_0` is shorter, so that `segment_0`, the header and other
    information of size `get_ciphertext_offset()` align with
    `get_ciphertext_segment_size()`.

The format of the header is

```
header_size || salt || nonce_prefix
```

where:

*   header_size is 1 byte determining the size of the header
*   salt is a salt used in the key derivation. It has the same size as the key
    size chosen for the block cipher.
*   nonce_prefix is the prefix of the nonce. Currently it has the same size of 7
    bytes for all encryption modes.

The salt is generated randomly on stream generation. The file key is derived as

```
HKDF(ikm=key, salt=salt, info=associated_data, len=key_size)
```

and each `segment_i` is encrypted using the IV

```
nonce_prefix || i || last_segment
```

where `i` is the segment number as 32 bit integer, `last_segment` is equal to 0
for all but the last segment, where it equals 1. The segment is encrypted
without associated data being set. Note that the `header_size` is completely
determined by the key parameters and should be checked independently.

#### AES-CTR-HMAC-HKDF

AES-CTR-HMAC-HKDF uses a nonce prefix of 7 bytes and sets the last 4 bytes of
the IV to zero, to get a 16 byte IV for use in CTR mode. The first ikm size
bytes of the key derivation result are used as key for CTR mode, the next 32
bytes are used as HMAC key. The tag is computed as the HMAC of

```
IV || ciphertext.
```

#### AES-GCM-HKDF

AES-GCM-HKDF uses a nonce prefix of 7 bytes to get 12 byte IVs for the segment
encryption. The key derived is the same size as the input key material.

### Envelope Encryption

Envelope encryption encrypts the data with a data encryption key `DEK` using
Tink's AEAD primitives. In addition the `DEK` is encrypted with an external
provider (e.g. GCP) and prepended to the `ciphertext`. The format for envelope
encryption is as follows:

```
DEK length || encrypted DEK || ciphertext
```

The `DEK length` is 4 bytes, storing the length of the `encrypted DEK` as a
32-bit big endian integer. The format of the `encrypted DEK` depends on the
external provider which was used for encrypting the `DEK`. The `ciphertext` will
have the exact same format as the AEAD primitive corresponding to the `DEK`.

### MAC

Tink follows the corresponding RFCs.

### PRF Set

Tink follows the corresponding RFCs. Note that for PRF Set the key type differs
from the MAC key type of the same algorithm by not including the outputlength.
PRF Set keys have to have a RAW output prefix type, as the key ID handling is
done by the user. This ensures the output is actually a PRF.

### Hybrid Encryption

Hybrid Encryption uses a Key Encryption Message (KEM) and a Data Encryption
Message (DEM). The general format is

```
KEM || DEM,
```

with the key type knowing how many bytes to parse for the KEM.

#### KEM

Depending on the key type, Tink uses compressed and uncompressed elliptic curve
points, following `RFC 8422/ANSI.X9-62.2005` encoding standards. For
uncompressed points, the byte `0x04` is followed by the `x` and the `y`
coordinate as fixed size integers. For compressed coordinates, the byte `0x02`
or `0x03` and the `x` coordinate as a fixed size integer is used. For `X25519`,
`RFC 7748` defining it is used (`x` coordinate as fixed size integer).

#### DEM

For the data encryption message, Tink uses the same format as the AEAD uses.
This includes specifying an IV.

#### Key derivation

First the x coordinate x_ss of the shared point is computed. The key for the
AEAD is then set to

```
HKDF(ikm = kem || x_ss, salt = salt_of_key, info = context_info, length = dem_key_size),
```

where kem is the full kem as bytes.

### Digital Signatures

Depending on the corresponding field in the key, the format of a digital
signature is either `IEEE P1363` format and `ASN.1 DER` format for ECDSA.

The `IEEE P1363` signature's format is `r || s`, where `r` and `s` are zero-padded
and have the same size in bytes as the order of the curve. For example, for
`NIST P-256` curve, `r` and `s` are zero-padded to 32 bytes.

The DER signature is encoded using
[`ASN.1`](https://tools.ietf.org/html/rfc5480#appendix-A):

```
ECDSA-Sig-Value :: = SEQUENCE { r INTEGER, s INTEGER }.
```

In particular, the encoding is:

```
0x30 || totalLength || 0x02 || r's length || r || 0x02 || s's length || s.
```

Tink follows the best practices for signature verification as outlined by
[bitcoin](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki).
