#!/bin/sh

# AesCtrHmacAead
tinkey create-key-template \
--type-url type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey \
--key-format "aes_ctr_key_format{params{iv_size:16},key_size:16}, \
hmac_key_format{params{hash:SHA256,tag_size:16},key_size:32}" > aead/AES128_CTR_HMAC_SHA256.ascii

tinkey create-key-template \
--type-url type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey \
--key-format "aes_ctr_key_format{params{iv_size:16}, key_size:32}, \
hmac_key_format{params{hash:SHA256,tag_size:32},key_size:32}" > aead/AES256_CTR_HMAC_SHA256.ascii

# AesEax
tinkey create-key-template \
--type-url type.googleapis.com/google.crypto.tink.AesEaxKey \
--key-format "params{iv_size:16}key_size:16" > aead/AES128_EAX.ascii

tinkey create-key-template \
--type-url type.googleapis.com/google.crypto.tink.AesEaxKey \
--key-format "params{iv_size:16}key_size:32" > aead/AES256_EAX.ascii

# AesGcmKey
tinkey create-key-template \
--type-url type.googleapis.com/google.crypto.tink.AesGcmKey \
--key-format "key_size:16" > aead/AES128_GCM.ascii

tinkey create-key-template \
--type-url type.googleapis.com/google.crypto.tink.AesGcmKey \
--key-format "key_size:32" > aead/AES256_GCM.ascii

# ChaCha20Poly1305
tinkey create-key-template \
--type-url type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key > aead/CHACHA20_POLY1305.ascii

tinkey create-key-template \
--type-url type.googleapis.com/google.crypto.tink.AesEaxKey \
--key-format "params{iv_size:16}key_size:32" > aead/AES256_EAX.ascii

# EcdsaPrivateKey
tinkey create-key-template \
--type-url type.googleapis.com/google.crypto.tink.EcdsaPrivateKey \
--key-format "params{hash_type:SHA256,curve:NIST_P256,encoding:DER}" > signature/ECDSA_P256.ascii

tinkey create-key-template \
--type-url type.googleapis.com/google.crypto.tink.EcdsaPrivateKey \
--key-format "params{hash_type:SHA512,curve:NIST_P384,encoding:DER}" > signature/ECDSA_P384.ascii

tinkey create-key-template \
--type-url type.googleapis.com/google.crypto.tink.EcdsaPrivateKey \
--key-format "params{hash_type:SHA512,curve:NIST_P521,encoding:DER}" > signature/ECDSA_P521.ascii

tinkey create-key-template \
--type-url type.googleapis.com/google.crypto.tink.Ed25519PrivateKey > signature/ED25519.ascii

# EciesAeadHkdfPrivateKey
tinkey create-key-template \
--type-url type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey \
--key-format "params{dem_params{aead_dem{type_url:\"type.googleapis.com/google.crypto.tink.AesGcmKey\",value:\"\020\020\"}}kem_params{hkdf_hash_type:SHA256,curve_type:NIST_P256}ec_point_format:UNCOMPRESSED}" > hybrid/ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM.ascii

tinkey create-key-template \
--type-url type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey \
--key-format "params{dem_params{aead_dem{type_url:\"type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey\",value:\"\n\006\n\002\b\020\020\020\022\b\n\004\b\003\020\020\020 \"}}kem_params{hkdf_hash_type:SHA256,curve_type:NIST_P256}ec_point_format:UNCOMPRESSED}" > hybrid/ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256.ascii

# HmacKey
tinkey create-key-template \
--type-url type.googleapis.com/google.crypto.tink.HmacKey \
--key-format "params{hash:SHA256,tag_size:16}key_size:32" > mac/HMAC_SHA256_128BITTAG.ascii

tinkey create-key-template \
--type-url type.googleapis.com/google.crypto.tink.HmacKey \
--key-format "params{hash:SHA256,tag_size:32}key_size:32" > mac/HMAC_SHA256_256BITTAG.ascii
