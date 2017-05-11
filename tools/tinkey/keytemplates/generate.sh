#!/bin/sh

# AesCtrHmacAeadKey
tinkey create-key-template \
--type-url type.googleapis.com/google.cloud.crypto.tink.AesCtrHmacAeadKey \
--key-format "aes_ctr_key_format{params{iv_size:12},key_size:16}, \
hmac_key_format{params{hash:SHA256,tag_size:16},key_size:32}" > aead/AES128CTR_96BITIV_HMACSHA256_128BITTAG.proto

tinkey create-key-template \
--type-url type.googleapis.com/google.cloud.crypto.tink.AesCtrHmacAeadKey \
--key-format "aes_ctr_key_format{params{iv_size:16},key_size:16}, \
hmac_key_format{params{hash:SHA256,tag_size:16},key_size:32}" > aead/AES128CTR_128BITIV_HMACSHA256_128BITTAG.proto

tinkey create-key-template \
--type-url type.googleapis.com/google.cloud.crypto.tink.AesCtrHmacAeadKey \
--key-format "aes_ctr_key_format{params{iv_size:12},key_size:32}, \
hmac_key_format{params{hash:SHA256,tag_size:32},key_size:32}" > aead/AES256CTR_96BITIV_HMACSHA256_256BITTAG.proto

tinkey create-key-template \
--type-url type.googleapis.com/google.cloud.crypto.tink.AesCtrHmacAeadKey \
--key-format "aes_ctr_key_format{params{iv_size:16}, key_size:32}, \
hmac_key_format{params{hash:SHA256,tag_size:32},key_size:32}" > aead/AES256CTR_128BITIV_HMACSHA256_256BITTAG.proto

# AesEaxKey
tinkey create-key-template \
--type-url type.googleapis.com/google.cloud.crypto.tink.AesEaxKey \
--key-format "params{iv_size:12}key_size:16" > aead/AES128EAX_96BITIV.proto

tinkey create-key-template \
--type-url type.googleapis.com/google.cloud.crypto.tink.AesEaxKey \
--key-format "params{iv_size:16}key_size:16" > aead/AES128EAX_128BITIV.proto

tinkey create-key-template \
--type-url type.googleapis.com/google.cloud.crypto.tink.AesEaxKey \
--key-format "params{iv_size:12}key_size:32" > aead/AES256EAX_96BITIV.proto

tinkey create-key-template \
--type-url type.googleapis.com/google.cloud.crypto.tink.AesEaxKey \
--key-format "params{iv_size:16}key_size:32" > aead/AES256EAX_128BITIV.proto

# AesGcmKey
tinkey create-key-template \
--type-url type.googleapis.com/google.cloud.crypto.tink.AesGcmKey \
--key-format "key_size:16" > aead/AES128GCM.proto

tinkey create-key-template \
--type-url type.googleapis.com/google.cloud.crypto.tink.AesGcmKey \
--key-format "key_size:32" > aead/AES256GCM.proto

# EcdsaPrivateKey
tinkey create-key-template \
--type-url type.googleapis.com/google.cloud.crypto.tink.EcdsaPrivateKey \
--key-format "params{hash_type:SHA256,curve:NIST_P256,encoding:DER}" > signature/ECDSA_P256_SHA256.proto

# EciesAeadHkdfPrivateKey
tinkey create-key-template \
--type-url type.googleapis.com/google.cloud.crypto.tink.EciesAeadHkdfPrivateKey \
--key-format "params{dem_params{aead_dem{type_url:\"type.googleapis.com/google.cloud.crypto.tink.AesGcmKey\",value:\"\020\020\"}}kem_params{hkdf_hash_type:SHA256,curve_type:NIST_P256}ec_point_format:UNCOMPRESSED}" > hybrid/ECIES_P256_HKDFHMACSHA256_AES128GCM.proto

tinkey create-key-template \
--type-url type.googleapis.com/google.cloud.crypto.tink.EciesAeadHkdfPrivateKey \
--key-format "params{dem_params{aead_dem{type_url:\"type.googleapis.com/google.cloud.crypto.tink.AesGcmKey\",value:\"\020 \"}}kem_params{hkdf_hash_type:SHA256,curve_type:NIST_P256}ec_point_format:UNCOMPRESSED}" > hybrid/ECIES_P256_HKDFHMACSHA256_AES256GCM.proto

tinkey create-key-template \
--type-url type.googleapis.com/google.cloud.crypto.tink.EciesAeadHkdfPrivateKey \
--key-format "params{dem_params{aead_dem{type_url:\"type.googleapis.com/google.cloud.crypto.tink.AesCtrHmacAeadKey\",value:\"\n\006\n\002\b\020\020\020\022\b\n\004\b\003\020\020\020 \"}}kem_params{hkdf_hash_type:SHA256,curve_type:NIST_P256}ec_point_format:UNCOMPRESSED}" > hybrid/ECIES_P256_HKDFHMACSHA256_AES128CTR_128BITIV_HMACSHA256_128BITTAG.proto

tinkey create-key-template \
--type-url type.googleapis.com/google.cloud.crypto.tink.EciesAeadHkdfPrivateKey \
--key-format "params{dem_params{aead_dem{type_url:\"type.googleapis.com/google.cloud.crypto.tink.AesCtrHmacAeadKey\",value:\"\n\006\n\002\b\020\020 \022\b\n\004\b\003\020 \020 \"}}kem_params{hkdf_hash_type:SHA256,curve_type:NIST_P256}ec_point_format:UNCOMPRESSED}" > hybrid/ECIES_P256_HKDFHMACSHA256_AES256CTR_128BITIV_HMACSHA256_256BITTAG.proto

# HmacKey
tinkey create-key-template \
--type-url type.googleapis.com/google.cloud.crypto.tink.HmacKey \
--key-format "params{hash:SHA256,tag_size:16}key_size:32" > mac/HMACSHA256_128BITTAG.proto

tinkey create-key-template \
--type-url type.googleapis.com/google.cloud.crypto.tink.HmacKey \
--key-format "params{hash:SHA256,tag_size:32}key_size:32" > mac/HMACSHA256_256BITTAG.proto
