tink_module(subtle)

add_subdirectory(prf)
add_subdirectory(mac)

tink_cc_library(
  NAME subtle
  SRCS
    aes_gcm_boringssl.h
    aes_siv_boringssl.h
    common_enums.h
    encrypt_then_authenticate.h
    hkdf.h
    hmac_boringssl.h
    ind_cpa_cipher.h
    random.h
  DEPS
    tink::subtle::aes_gcm_boringssl
    tink::subtle::aes_siv_boringssl
    tink::subtle::common_enums
    tink::subtle::encrypt_then_authenticate
    tink::subtle::hkdf
    tink::subtle::hmac_boringssl
    tink::subtle::random
    absl::core_headers
    absl::strings
    absl::span
    crypto
    tink::core::aead
    tink::core::deterministic_aead
    tink::core::mac
    tink::aead::internal::aead_from_zero_copy
    tink::aead::internal::zero_copy_aead
    tink::internal::fips_utils
    tink::internal::ssl_unique_ptr
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
  PUBLIC
)

add_library(tink::subtle ALIAS tink_subtle_subtle)

tink_cc_library(
  NAME ind_cpa_cipher
  SRCS
    ind_cpa_cipher.h
  DEPS
    absl::strings
    tink::util::statusor
)

tink_cc_library(
  NAME ecies_hkdf_recipient_kem_boringssl
  SRCS
    ecies_hkdf_recipient_kem_boringssl.cc
    ecies_hkdf_recipient_kem_boringssl.h
  DEPS
    tink::subtle::common_enums
    tink::subtle::hkdf
    absl::memory
    absl::status
    absl::strings
    crypto
    tink::internal::ec_util
    tink::internal::fips_utils
    tink::internal::ssl_unique_ptr
    tink::util::errors
    tink::util::secret_data
    tink::util::statusor
)

tink_cc_library(
  NAME ecies_hkdf_sender_kem_boringssl
  SRCS
    ecies_hkdf_sender_kem_boringssl.cc
    ecies_hkdf_sender_kem_boringssl.h
  DEPS
    tink::subtle::common_enums
    tink::subtle::hkdf
    absl::memory
    absl::status
    absl::strings
    crypto
    tink::internal::ec_util
    tink::internal::fips_utils
    tink::internal::ssl_unique_ptr
    tink::util::secret_data
    tink::util::statusor
)

tink_cc_library(
  NAME ec_util
  SRCS
    ec_util.h
  DEPS
    tink::subtle::common_enums
    absl::core_headers
    crypto
    tink::internal::ec_util
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME ed25519_sign_boringssl
  SRCS
    ed25519_sign_boringssl.cc
    ed25519_sign_boringssl.h
  DEPS
    absl::memory
    absl::status
    absl::strings
    absl::str_format
    crypto
    tink::core::public_key_sign
    tink::config::tink_fips
    tink::internal::util
    tink::util::secret_data
    tink::util::statusor
)

tink_cc_library(
  NAME ed25519_verify_boringssl
  SRCS
    ed25519_verify_boringssl.cc
    ed25519_verify_boringssl.h
  DEPS
    absl::status
    absl::strings
    absl::str_format
    crypto
    tink::core::public_key_verify
    tink::internal::fips_utils
    tink::internal::util
    tink::util::statusor
)

tink_cc_library(
  NAME hkdf
  SRCS
    hkdf.cc
    hkdf.h
  DEPS
    tink::subtle::common_enums
    tink::subtle::subtle_util
    absl::algorithm_container
    absl::status
    absl::strings
    absl::span
    crypto
    tink::internal::md_util
    tink::internal::ssl_unique_ptr
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_cmac_boringssl
  SRCS
    aes_cmac_boringssl.cc
    aes_cmac_boringssl.h
  DEPS
    tink::subtle::subtle_util
    absl::memory
    absl::status
    crypto
    tink::core::mac
    tink::internal::fips_utils
    tink::internal::ssl_unique_ptr
    tink::internal::util
    tink::util::errors
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hmac_boringssl
  SRCS
    hmac_boringssl.cc
    hmac_boringssl.h
  DEPS
    tink::subtle::common_enums
    absl::memory
    absl::status
    absl::strings
    crypto
    tink::core::mac
    tink::internal::fips_utils
    tink::internal::md_util
    tink::internal::util
    tink::util::errors
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME ecdsa_sign_boringssl
  SRCS
    ecdsa_sign_boringssl.cc
    ecdsa_sign_boringssl.h
  DEPS
    tink::subtle::common_enums
    tink::subtle::subtle_util_boringssl
    absl::status
    absl::strings
    crypto
    tink::core::public_key_sign
    tink::internal::bn_util
    tink::internal::ec_util
    tink::internal::err_util
    tink::internal::fips_utils
    tink::internal::md_util
    tink::internal::ssl_unique_ptr
    tink::internal::util
    tink::util::errors
    tink::util::statusor
)

tink_cc_library(
  NAME ecdsa_verify_boringssl
  SRCS
    ecdsa_verify_boringssl.cc
    ecdsa_verify_boringssl.h
  DEPS
    tink::subtle::common_enums
    tink::subtle::subtle_util_boringssl
    absl::status
    absl::strings
    crypto
    tink::core::public_key_verify
    tink::internal::ec_util
    tink::internal::err_util
    tink::internal::fips_utils
    tink::internal::md_util
    tink::internal::ssl_unique_ptr
    tink::internal::util
    tink::util::errors
    tink::util::status
)

tink_cc_library(
  NAME rsa_ssa_pss_verify_boringssl
  SRCS
    rsa_ssa_pss_verify_boringssl.cc
    rsa_ssa_pss_verify_boringssl.h
  DEPS
    tink::subtle::common_enums
    absl::status
    absl::strings
    crypto
    tink::core::public_key_verify
    tink::internal::fips_utils
    tink::internal::md_util
    tink::internal::rsa_util
    tink::internal::ssl_unique_ptr
    tink::internal::util
    tink::util::errors
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME rsa_ssa_pss_sign_boringssl
  SRCS
    rsa_ssa_pss_sign_boringssl.cc
    rsa_ssa_pss_sign_boringssl.h
  DEPS
    tink::subtle::common_enums
    tink::subtle::subtle_util
    absl::memory
    absl::status
    absl::strings
    crypto
    tink::core::public_key_sign
    tink::internal::err_util
    tink::internal::fips_utils
    tink::internal::md_util
    tink::internal::rsa_util
    tink::internal::ssl_unique_ptr
    tink::internal::util
    tink::util::statusor
)

tink_cc_library(
  NAME rsa_ssa_pkcs1_verify_boringssl
  SRCS
    rsa_ssa_pkcs1_verify_boringssl.cc
    rsa_ssa_pkcs1_verify_boringssl.h
  DEPS
    tink::subtle::common_enums
    absl::status
    absl::strings
    crypto
    tink::core::public_key_verify
    tink::internal::fips_utils
    tink::internal::md_util
    tink::internal::rsa_util
    tink::internal::ssl_unique_ptr
    tink::internal::util
    tink::util::errors
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME rsa_ssa_pkcs1_sign_boringssl
  SRCS
    rsa_ssa_pkcs1_sign_boringssl.cc
    rsa_ssa_pkcs1_sign_boringssl.h
  DEPS
    tink::subtle::common_enums
    tink::subtle::subtle_util
    absl::memory
    absl::status
    absl::strings
    crypto
    tink::core::public_key_sign
    tink::internal::bn_util
    tink::internal::err_util
    tink::internal::fips_utils
    tink::internal::md_util
    tink::internal::rsa_util
    tink::internal::ssl_unique_ptr
    tink::internal::util
    tink::util::statusor
)

tink_cc_library(
  NAME aes_gcm_boringssl
  SRCS
    aes_gcm_boringssl.cc
    aes_gcm_boringssl.h
  DEPS
    absl::memory
    absl::strings
    tink::core::aead
    tink::aead::internal::aead_from_zero_copy
    tink::aead::internal::zero_copy_aead
    tink::aead::internal::zero_copy_aes_gcm_boringssl
    tink::internal::fips_utils
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_gcm_hkdf_stream_segment_decrypter
  SRCS
    aes_gcm_hkdf_stream_segment_decrypter.cc
    aes_gcm_hkdf_stream_segment_decrypter.h
  DEPS
    tink::subtle::aes_gcm_hkdf_stream_segment_encrypter
    tink::subtle::common_enums
    tink::subtle::hkdf
    tink::subtle::random
    tink::subtle::stream_segment_decrypter
    absl::algorithm_container
    absl::config
    absl::memory
    absl::status
    absl::strings
    absl::span
    tink::aead::internal::ssl_aead
    tink::internal::err_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_gcm_hkdf_stream_segment_encrypter
  SRCS
    aes_gcm_hkdf_stream_segment_encrypter.cc
    aes_gcm_hkdf_stream_segment_encrypter.h
  DEPS
    tink::subtle::random
    tink::subtle::stream_segment_encrypter
    tink::subtle::subtle_util
    absl::algorithm_container
    absl::config
    absl::memory
    absl::status
    absl::strings
    absl::span
    tink::aead::internal::ssl_aead
    tink::internal::err_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_gcm_hkdf_streaming
  SRCS
    aes_gcm_hkdf_streaming.cc
    aes_gcm_hkdf_streaming.h
  DEPS
    tink::subtle::aes_gcm_hkdf_stream_segment_decrypter
    tink::subtle::aes_gcm_hkdf_stream_segment_encrypter
    tink::subtle::common_enums
    tink::subtle::hkdf
    tink::subtle::nonce_based_streaming_aead
    tink::subtle::random
    absl::memory
    absl::status
    crypto
    tink::internal::fips_utils
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_ctr_hmac_streaming
  SRCS
    aes_ctr_hmac_streaming.cc
    aes_ctr_hmac_streaming.h
  DEPS
    tink::subtle::common_enums
    tink::subtle::hkdf
    tink::subtle::hmac_boringssl
    tink::subtle::nonce_based_streaming_aead
    tink::subtle::random
    tink::subtle::stream_segment_decrypter
    tink::subtle::stream_segment_encrypter
    tink::subtle::subtle_util
    absl::memory
    absl::status
    absl::strings
    crypto
    tink::core::mac
    tink::aead::internal::aead_util
    tink::internal::fips_utils
    tink::internal::ssl_unique_ptr
    tink::util::errors
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_eax_boringssl
  SRCS
    aes_eax_boringssl.cc
    aes_eax_boringssl.h
  DEPS
    tink::subtle::random
    tink::subtle::subtle_util
    absl::algorithm_container
    absl::config
    absl::memory
    absl::status
    absl::strings
    absl::span
    crypto
    tink::core::aead
    tink::internal::fips_utils
    tink::internal::util
    tink::util::errors
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME encrypt_then_authenticate
  SRCS
    encrypt_then_authenticate.cc
    encrypt_then_authenticate.h
  DEPS
    tink::subtle::ind_cpa_cipher
    absl::status
    absl::strings
    tink::core::aead
    tink::core::mac
    tink::internal::util
    tink::util::errors
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_ctr_boringssl
  SRCS
    aes_ctr_boringssl.cc
    aes_ctr_boringssl.h
  DEPS
    tink::subtle::ind_cpa_cipher
    tink::subtle::random
    tink::subtle::subtle_util
    absl::memory
    absl::status
    crypto
    tink::aead::internal::aead_util
    tink::internal::fips_utils
    tink::internal::ssl_unique_ptr
    tink::internal::util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME random
  SRCS
    random.cc
    random.h
  DEPS
    tink::subtle::subtle_util
    absl::status
    absl::strings
    absl::span
    crypto
    tink::util::secret_data
    tink::util::status
)

tink_cc_library(
  NAME xchacha20_poly1305_boringssl
  SRCS
    xchacha20_poly1305_boringssl.cc
    xchacha20_poly1305_boringssl.h
  DEPS
    tink::subtle::random
    tink::subtle::subtle_util
    absl::memory
    absl::status
    absl::strings
    absl::span
    tink::core::aead
    tink::aead::internal::ssl_aead
    tink::internal::fips_utils
    tink::internal::util
    tink::util::errors
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_siv_boringssl
  SRCS
    aes_siv_boringssl.cc
    aes_siv_boringssl.h
  DEPS
    absl::memory
    absl::status
    absl::strings
    absl::span
    crypto
    tink::core::deterministic_aead
    tink::internal::fips_utils
    tink::util::errors
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_gcm_siv_boringssl
  SRCS
    aes_gcm_siv_boringssl.cc
    aes_gcm_siv_boringssl.h
  DEPS
    tink::subtle::random
    tink::subtle::subtle_util
    absl::memory
    absl::status
    absl::strings
    absl::span
    tink::core::aead
    tink::aead::internal::ssl_aead
    tink::internal::fips_utils
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME common_enums
  SRCS
    common_enums.cc
    common_enums.h
  DEPS
    absl::strings
)

tink_cc_library(
  NAME subtle_util
  SRCS
    subtle_util.cc
    subtle_util.h
)

tink_cc_library(
  NAME subtle_util_boringssl
  SRCS
    subtle_util_boringssl.h
  DEPS
    tink::subtle::common_enums
    tink::subtle::random
    tink::subtle::subtle_util
    absl::core_headers
    absl::memory
    absl::status
    absl::strings
    absl::span
    crypto
    tink::aead::internal::aead_util
    tink::config::tink_fips
    tink::internal::bn_util
    tink::internal::ec_util
    tink::internal::err_util
    tink::internal::md_util
    tink::internal::rsa_util
    tink::internal::ssl_unique_ptr
    tink::internal::util
    tink::util::errors
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME wycheproof_util
  SRCS
    wycheproof_util.cc
    wycheproof_util.h
  DEPS
    tink::subtle::common_enums
    absl::status
    absl::strings
    rapidjson
    tink::internal::test_file_util
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME stream_segment_decrypter
  SRCS
    stream_segment_decrypter.h
  DEPS
    tink::util::status
)

tink_cc_library(
  NAME stream_segment_encrypter
  SRCS
    stream_segment_encrypter.h
  DEPS
    tink::util::status
)

tink_cc_library(
  NAME streaming_aead_decrypting_stream
  SRCS
    streaming_aead_decrypting_stream.cc
    streaming_aead_decrypting_stream.h
  DEPS
    tink::subtle::stream_segment_decrypter
    absl::memory
    absl::status
    tink::core::input_stream
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME streaming_aead_encrypting_stream
  SRCS
    streaming_aead_encrypting_stream.cc
    streaming_aead_encrypting_stream.h
  DEPS
    tink::subtle::stream_segment_encrypter
    absl::memory
    absl::status
    tink::core::output_stream
    tink::util::statusor
)

tink_cc_library(
  NAME nonce_based_streaming_aead
  SRCS
    nonce_based_streaming_aead.cc
    nonce_based_streaming_aead.h
  DEPS
    tink::subtle::decrypting_random_access_stream
    tink::subtle::stream_segment_decrypter
    tink::subtle::stream_segment_encrypter
    tink::subtle::streaming_aead_decrypting_stream
    tink::subtle::streaming_aead_encrypting_stream
    absl::strings
    tink::core::input_stream
    tink::core::output_stream
    tink::core::random_access_stream
    tink::core::streaming_aead
    tink::util::statusor
)

tink_cc_library(
  NAME test_util
  SRCS
    test_util.cc
    test_util.h
  DEPS
    tink::subtle::nonce_based_streaming_aead
    tink::subtle::stream_segment_decrypter
    tink::subtle::stream_segment_encrypter
    absl::memory
    absl::status
    absl::strings
    tink::core::input_stream
    tink::core::output_stream
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aead_test_util
  SRCS
    aead_test_util.cc
    aead_test_util.h
  DEPS
    tink::subtle::test_util
    absl::strings
    tink::core::aead
    tink::aead::cord_aead
    tink::util::status
)

tink_cc_library(
  NAME streaming_aead_test_util
  SRCS
    streaming_aead_test_util.cc
    streaming_aead_test_util.h
  DEPS
    tink::subtle::test_util
    absl::strings
    tink::core::random_access_stream
    tink::core::streaming_aead
    tink::util::buffer
    tink::util::file_random_access_stream
    tink::util::istream_input_stream
    tink::util::ostream_output_stream
    tink::util::status
    tink::util::test_util
)

tink_cc_library(
  NAME hybrid_test_util
  SRCS
    hybrid_test_util.cc
    hybrid_test_util.h
  DEPS
    absl::status
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::util::status
)

tink_cc_library(
  NAME decrypting_random_access_stream
  SRCS
    decrypting_random_access_stream.cc
    decrypting_random_access_stream.h
  DEPS
    tink::subtle::stream_segment_decrypter
    absl::core_headers
    absl::memory
    absl::status
    absl::strings
    absl::synchronization
    tink::core::random_access_stream
    tink::util::buffer
    tink::util::errors
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME streaming_mac_impl
  SRCS
    streaming_mac_impl.cc
    streaming_mac_impl.h
  DEPS
    absl::memory
    absl::status
    tink::core::streaming_mac
    tink::subtle::mac::stateful_mac
    tink::util::status
)

tink_cc_library(
  NAME stateful_hmac_boringssl
  SRCS
    stateful_hmac_boringssl.cc
    stateful_hmac_boringssl.h
  DEPS
    tink::subtle::common_enums
    absl::memory
    absl::status
    crypto
    tink::internal::md_util
    tink::internal::ssl_unique_ptr
    tink::internal::util
    tink::subtle::mac::stateful_mac
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME stateful_cmac_boringssl
  SRCS
    stateful_cmac_boringssl.cc
    stateful_cmac_boringssl.h
  DEPS
    tink::subtle::common_enums
    absl::memory
    absl::status
    crypto
    tink::internal::ssl_unique_ptr
    tink::internal::util
    tink::subtle::mac::stateful_mac
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME pem_parser_boringssl
  SRCS
    pem_parser_boringssl.cc
    pem_parser_boringssl.h
  DEPS
    tink::subtle::common_enums
    tink::subtle::subtle_util_boringssl
    absl::memory
    absl::status
    absl::strings
    crypto
    tink::internal::bn_util
    tink::internal::rsa_util
    tink::internal::ssl_unique_ptr
    tink::util::status
    tink::util::statusor
)

# tests

tink_cc_test(
  NAME ecies_hkdf_recipient_kem_boringssl_test
  SRCS
    ecies_hkdf_recipient_kem_boringssl_test.cc
  DEPS
    tink::subtle::common_enums
    tink::subtle::ecies_hkdf_recipient_kem_boringssl
    gmock
    absl::status
    tink::config::tink_fips
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME ecies_hkdf_sender_kem_boringssl_test
  SRCS
    ecies_hkdf_sender_kem_boringssl_test.cc
  DEPS
    tink::subtle::common_enums
    tink::subtle::ecies_hkdf_recipient_kem_boringssl
    tink::subtle::ecies_hkdf_sender_kem_boringssl
    gmock
    absl::status
    tink::config::tink_fips
    tink::internal::ec_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME hkdf_test
  SRCS
    hkdf_test.cc
  DEPS
    tink::subtle::common_enums
    tink::subtle::hkdf
    gmock
    absl::strings
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME aes_cmac_boringssl_test
  SRCS
    aes_cmac_boringssl_test.cc
  DEPS
    tink::subtle::aes_cmac_boringssl
    tink::subtle::common_enums
    gmock
    absl::status
    absl::strings
    tink::core::mac
    tink::config::tink_fips
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME hmac_boringssl_test
  SRCS
    hmac_boringssl_test.cc
  DEPS
    tink::subtle::common_enums
    tink::subtle::hmac_boringssl
    gmock
    absl::status
    absl::strings
    tink::core::mac
    tink::config::tink_fips
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_gcm_boringssl_test
  SRCS
    aes_gcm_boringssl_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::subtle::aes_gcm_boringssl
    gmock
    absl::status
    absl::strings
    tink::aead::internal::wycheproof_aead
    tink::config::tink_fips
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_gcm_hkdf_stream_segment_decrypter_test
  SRCS
    aes_gcm_hkdf_stream_segment_decrypter_test.cc
  DEPS
    tink::subtle::aes_gcm_hkdf_stream_segment_decrypter
    tink::subtle::aes_gcm_hkdf_stream_segment_encrypter
    tink::subtle::common_enums
    tink::subtle::hkdf
    tink::subtle::random
    tink::subtle::stream_segment_encrypter
    gmock
    absl::strings
    tink::util::status
    tink::util::statusor
    tink::util::test_util
)

tink_cc_test(
  NAME aes_gcm_hkdf_stream_segment_encrypter_test
  SRCS
    aes_gcm_hkdf_stream_segment_encrypter_test.cc
  DEPS
    tink::subtle::aes_gcm_hkdf_stream_segment_encrypter
    tink::subtle::random
    gmock
    absl::status
    absl::strings
    tink::util::status
    tink::util::statusor
    tink::util::test_util
)

tink_cc_test(
  NAME aes_gcm_hkdf_streaming_test
  SRCS
    aes_gcm_hkdf_streaming_test.cc
  DEPS
    tink::subtle::aes_gcm_hkdf_streaming
    tink::subtle::common_enums
    tink::subtle::random
    tink::subtle::streaming_aead_test_util
    tink::subtle::test_util
    gmock
    absl::memory
    absl::status
    absl::strings
    tink::core::output_stream
    tink::config::tink_fips
    tink::util::istream_input_stream
    tink::util::ostream_output_stream
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_ctr_hmac_streaming_test
  SRCS
    aes_ctr_hmac_streaming_test.cc
  DEPS
    tink::subtle::aes_ctr_hmac_streaming
    tink::subtle::common_enums
    tink::subtle::random
    tink::subtle::stream_segment_decrypter
    tink::subtle::stream_segment_encrypter
    tink::subtle::streaming_aead_test_util
    gmock
    absl::status
    absl::strings
    tink::config::tink_fips
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME aes_eax_boringssl_test
  SRCS
    aes_eax_boringssl_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::subtle::aes_eax_boringssl
    tink::subtle::wycheproof_util
    gmock
    absl::status
    absl::strings
    crypto
    tink::config::tink_fips
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME encrypt_then_authenticate_test
  SRCS
    encrypt_then_authenticate_test.cc
  DEPS
    tink::subtle::aes_ctr_boringssl
    tink::subtle::common_enums
    tink::subtle::encrypt_then_authenticate
    tink::subtle::hmac_boringssl
    tink::subtle::random
    gmock
    absl::strings
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_util
)

tink_cc_test(
  NAME aes_ctr_boringssl_test
  SRCS
    aes_ctr_boringssl_test.cc
  DEPS
    tink::subtle::aes_ctr_boringssl
    tink::subtle::random
    gmock
    absl::status
    tink::config::tink_fips
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME aes_siv_boringssl_test
  SRCS
    aes_siv_boringssl_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::subtle::aes_siv_boringssl
    tink::subtle::wycheproof_util
    gmock
    absl::status
    tink::config::tink_fips
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME ecdsa_sign_boringssl_test
  SRCS
    ecdsa_sign_boringssl_test.cc
  DEPS
    tink::subtle::common_enums
    tink::subtle::ecdsa_sign_boringssl
    tink::subtle::ecdsa_verify_boringssl
    tink::subtle::subtle_util_boringssl
    gmock
    absl::status
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::config::tink_fips
    tink::internal::ec_util
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME ecdsa_verify_boringssl_test
  SRCS
    ecdsa_verify_boringssl_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::subtle::common_enums
    tink::subtle::ecdsa_sign_boringssl
    tink::subtle::ecdsa_verify_boringssl
    tink::subtle::subtle_util_boringssl
    tink::subtle::wycheproof_util
    gmock
    absl::status
    absl::strings
    rapidjson
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::config::tink_fips
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME ed25519_sign_boringssl_test
  SRCS
    ed25519_sign_boringssl_test.cc
  DEPS
    tink::subtle::ed25519_sign_boringssl
    tink::subtle::ed25519_verify_boringssl
    tink::subtle::random
    gmock
    absl::status
    absl::strings
    crypto
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::config::tink_fips
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME ed25519_verify_boringssl_test
  SRCS
    ed25519_verify_boringssl_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::subtle::ed25519_sign_boringssl
    tink::subtle::ed25519_verify_boringssl
    tink::subtle::wycheproof_util
    gmock
    absl::status
    absl::strings
    crypto
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::config::tink_fips
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME rsa_ssa_pss_verify_boringssl_test
  SRCS
    rsa_ssa_pss_verify_boringssl_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::subtle::common_enums
    tink::subtle::rsa_ssa_pss_verify_boringssl
    tink::subtle::wycheproof_util
    gmock
    absl::status
    absl::strings
    rapidjson
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::config::tink_fips
    tink::internal::err_util
    tink::internal::rsa_util
    tink::internal::ssl_unique_ptr
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME rsa_ssa_pss_sign_boringssl_test
  SRCS
    rsa_ssa_pss_sign_boringssl_test.cc
  DEPS
    tink::subtle::rsa_ssa_pss_sign_boringssl
    tink::subtle::rsa_ssa_pss_verify_boringssl
    gmock
    absl::status
    absl::strings
    crypto
    tink::config::tink_fips
    tink::internal::rsa_util
    tink::internal::ssl_unique_ptr
    tink::util::test_matchers
)

tink_cc_test(
  NAME rsa_ssa_pkcs1_verify_boringssl_test
  SRCS
    rsa_ssa_pkcs1_verify_boringssl_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::subtle::common_enums
    tink::subtle::rsa_ssa_pkcs1_verify_boringssl
    tink::subtle::wycheproof_util
    gmock
    absl::status
    absl::strings
    crypto
    rapidjson
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::config::tink_fips
    tink::internal::err_util
    tink::internal::rsa_util
    tink::internal::ssl_unique_ptr
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME rsa_ssa_pkcs1_sign_boringssl_test
  SRCS
    rsa_ssa_pkcs1_sign_boringssl_test.cc
  DEPS
    tink::subtle::rsa_ssa_pkcs1_sign_boringssl
    tink::subtle::rsa_ssa_pkcs1_verify_boringssl
    gmock
    absl::status
    absl::strings
    crypto
    tink::config::tink_fips
    tink::internal::rsa_util
    tink::internal::ssl_unique_ptr
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_gcm_siv_boringssl_test
  SRCS
    aes_gcm_siv_boringssl_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::subtle::aes_gcm_siv_boringssl
    tink::subtle::subtle_util
    gmock
    absl::status
    absl::strings
    tink::aead::internal::wycheproof_aead
    tink::config::tink_fips
    tink::internal::ssl_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME random_test
  SRCS
    random_test.cc
  DEPS
    tink::subtle::random
    gmock
    absl::flat_hash_set
    absl::span
    tink::util::secret_data
    tink::util::test_matchers
)

tink_cc_test(
  NAME common_enums_test
  SRCS
    common_enums_test.cc
  DEPS
    tink::subtle::common_enums
    gmock
)

tink_cc_test(
  NAME subtle_util_test
  SRCS
    subtle_util_test.cc
  DEPS
    tink::subtle::subtle_util
    gmock
)

tink_cc_test(
  NAME xchacha20_poly1305_boringssl_test
  SRCS
    xchacha20_poly1305_boringssl_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::subtle::subtle_util
    tink::subtle::xchacha20_poly1305_boringssl
    gmock
    absl::status
    absl::strings
    tink::aead::internal::wycheproof_aead
    tink::config::tink_fips
    tink::internal::ssl_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME streaming_aead_decrypting_stream_test
  SRCS
    streaming_aead_decrypting_stream_test.cc
  DEPS
    tink::subtle::random
    tink::subtle::stream_segment_decrypter
    tink::subtle::streaming_aead_decrypting_stream
    tink::subtle::test_util
    gmock
    absl::memory
    absl::strings
    tink::core::input_stream
    tink::util::istream_input_stream
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME streaming_aead_encrypting_stream_test
  SRCS
    streaming_aead_encrypting_stream_test.cc
  DEPS
    tink::subtle::random
    tink::subtle::stream_segment_encrypter
    tink::subtle::streaming_aead_encrypting_stream
    tink::subtle::test_util
    gmock
    absl::memory
    absl::strings
    tink::core::output_stream
    tink::util::ostream_output_stream
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME aead_test_util_test
  SRCS
    aead_test_util_test.cc
  DEPS
    tink::subtle::aead_test_util
    gmock
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME streaming_aead_test_util_test
  SRCS
    streaming_aead_test_util_test.cc
  DEPS
    tink::subtle::streaming_aead_test_util
    gmock
    absl::status
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME hybrid_test_util_test
  SRCS
    hybrid_test_util_test.cc
  DEPS
    tink::subtle::hybrid_test_util
    gmock
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME decrypting_random_access_stream_test
  SRCS
    decrypting_random_access_stream_test.cc
  DEPS
    tink::subtle::decrypting_random_access_stream
    tink::subtle::random
    tink::subtle::test_util
    gmock
    absl::memory
    absl::status
    absl::strings
    tink::core::output_stream
    tink::core::random_access_stream
    tink::core::streaming_aead
    tink::util::file_random_access_stream
    tink::util::ostream_output_stream
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME streaming_mac_impl_test
  SRCS
    streaming_mac_impl_test.cc
  DEPS
    tink::subtle::random
    tink::subtle::streaming_mac_impl
    tink::subtle::test_util
    gmock
    absl::status
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME stateful_hmac_boringssl_test
  SRCS
    stateful_hmac_boringssl_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::subtle::common_enums
    tink::subtle::stateful_hmac_boringssl
    tink::subtle::wycheproof_util
    gmock
    absl::memory
    absl::status
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME stateful_cmac_boringssl_test
  SRCS
    stateful_cmac_boringssl_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::subtle::common_enums
    tink::subtle::stateful_cmac_boringssl
    tink::subtle::wycheproof_util
    gmock
    absl::memory
    absl::status
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME pem_parser_boringssl_test
  SRCS
    pem_parser_boringssl_test.cc
  DEPS
    tink::subtle::pem_parser_boringssl
    tink::subtle::subtle_util_boringssl
    gmock
    absl::status
    absl::strings
    crypto
    tink::internal::bn_util
    tink::internal::err_util
    tink::internal::rsa_util
    tink::internal::ssl_unique_ptr
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

