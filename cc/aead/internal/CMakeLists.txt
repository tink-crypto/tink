tink_module(aead::internal)

tink_cc_library(
  NAME aead_util
  SRCS
    aead_util.cc
    aead_util.h
  DEPS
    absl::flat_hash_set
    absl::status
    absl::string_view
    crypto
    tink::util::errors
    tink::util::statusor
)

tink_cc_library(
  NAME wycheproof_aead
  SRCS
    wycheproof_aead.cc
    wycheproof_aead.h
  DEPS
    absl::strings
    tink::subtle::wycheproof_util
    tink::util::statusor
  TESTONLY
)

tink_cc_library(
  NAME ssl_aead
  SRCS
    ssl_aead.cc
    ssl_aead.h
  DEPS
    tink::aead::internal::aead_util
    absl::core_headers
    absl::cleanup
    absl::memory
    absl::status
    absl::strings
    absl::span
    crypto
    tink::internal::call_with_core_dump_protection
    tink::internal::err_util
    tink::internal::ssl_unique_ptr
    tink::internal::util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME cord_aes_gcm_boringssl
  SRCS
    cord_aes_gcm_boringssl.cc
    cord_aes_gcm_boringssl.h
  DEPS
    tink::aead::internal::aead_util
    absl::memory
    absl::status
    absl::cord
    absl::string_view
    crypto
    tink::aead::cord_aead
    tink::internal::ssl_unique_ptr
    tink::subtle::random
    tink::subtle::subtle_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME mock_zero_copy_aead
  SRCS
    mock_zero_copy_aead.h
  DEPS
    tink::aead::internal::zero_copy_aead
    gmock
    absl::strings
    absl::span
    tink::util::statusor
  TESTONLY
)

tink_cc_library(
  NAME aead_from_zero_copy
  SRCS
    aead_from_zero_copy.cc
    aead_from_zero_copy.h
  DEPS
    tink::aead::internal::zero_copy_aead
    absl::memory
    absl::status
    absl::string_view
    absl::span
    tink::core::aead
    tink::subtle::subtle_util
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME zero_copy_aead
  SRCS
    zero_copy_aead.h
  DEPS
    absl::strings
    absl::span
    tink::util::statusor
)

tink_cc_library(
  NAME zero_copy_aead_wrapper
  SRCS
    zero_copy_aead_wrapper.cc
    zero_copy_aead_wrapper.h
  DEPS
    tink::aead::internal::zero_copy_aead
    absl::memory
    absl::status
    absl::strings
    absl::span
    tink::core::aead
    tink::core::crypto_format
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::subtle::subtle_util
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME zero_copy_aes_gcm_boringssl
  SRCS
    zero_copy_aes_gcm_boringssl.cc
    zero_copy_aes_gcm_boringssl.h
  DEPS
    tink::aead::internal::aead_util
    tink::aead::internal::ssl_aead
    tink::aead::internal::zero_copy_aead
    absl::core_headers
    absl::memory
    absl::status
    absl::strings
    absl::span
    tink::internal::util
    tink::subtle::random
    tink::subtle::subtle_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME key_gen_config_v0
  SRCS
    key_gen_config_v0.cc
    key_gen_config_v0.h
  DEPS
    absl::memory
    tink::core::key_gen_configuration
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_eax_key_manager
    tink::aead::aes_gcm_key_manager
    tink::aead::aes_gcm_siv_key_manager
    tink::aead::xchacha20_poly1305_key_manager
    tink::internal::key_gen_configuration_impl
    tink::util::status
)

tink_cc_library(
  NAME config_v0
  SRCS
    config_v0.cc
    config_v0.h
  DEPS
    absl::memory
    tink::core::configuration
    tink::aead::aead_wrapper
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_eax_key_manager
    tink::aead::aes_gcm_key_manager
    tink::aead::aes_gcm_siv_key_manager
    tink::aead::xchacha20_poly1305_key_manager
    tink::internal::configuration_impl
    tink::util::status
)

tink_cc_test(
  NAME aead_util_test
  SRCS
    aead_util_test.cc
  DEPS
    tink::aead::internal::aead_util
    gmock
    crypto
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME ssl_aead_test
  SRCS
    ssl_aead_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::aead::internal::ssl_aead
    tink::aead::internal::wycheproof_aead
    gmock
    absl::flat_hash_set
    absl::status
    absl::strings
    absl::span
    tink::internal::fips_utils
    tink::internal::ssl_util
    tink::subtle::subtle_util
    tink::util::secret_data
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME cord_aes_gcm_boringssl_test
  SRCS
    cord_aes_gcm_boringssl_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::subtle::aes_gcm_boringssl
    tink::subtle::wycheproof_util
    tink::aead::cord_aead
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_util
    tink::util::test_matchers
    absl::strings
    absl::cord
    rapidjson
)

tink_cc_test(
  NAME aead_from_zero_copy_test
  SRCS
    aead_from_zero_copy_test.cc
  DEPS
    tink::aead::internal::aead_from_zero_copy
    tink::aead::internal::mock_zero_copy_aead
    gmock
    absl::memory
    absl::status
    absl::strings
    absl::span
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME zero_copy_aes_gcm_boringssl_test
  SRCS
    zero_copy_aes_gcm_boringssl_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::aead::internal::wycheproof_aead
    tink::aead::internal::zero_copy_aead
    tink::aead::internal::zero_copy_aes_gcm_boringssl
    gmock
    absl::status
    absl::strings
    absl::span
    crypto
    tink::subtle::subtle_util
    tink::util::secret_data
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME ssl_aead_large_inputs_test
  SRCS
    ssl_aead_large_inputs_test.cc
  DEPS
    tink::aead::internal::ssl_aead
    gmock
    absl::flat_hash_set
    absl::memory
    absl::status
    absl::strings
    absl::span
    tink::config::tink_fips
    tink::internal::ssl_util
    tink::internal::util
    tink::subtle::subtle_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME zero_copy_aead_wrapper_test
  SRCS
    zero_copy_aead_wrapper_test.cc
  DEPS
    tink::aead::internal::mock_zero_copy_aead
    tink::aead::internal::zero_copy_aead
    tink::aead::internal::zero_copy_aead_wrapper
    gmock
    absl::memory
    absl::status
    absl::string_view
    absl::span
    tink::core::aead
    tink::core::crypto_format
    tink::core::primitive_set
    tink::subtle::subtle_util
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME config_v0_test
  SRCS
    config_v0_test.cc
  DEPS
    tink::aead::internal::config_v0
    tink::aead::internal::key_gen_config_v0
    gmock
    tink::core::aead
    tink::core::configuration
    tink::core::key_gen_configuration
    tink::core::keyset_handle
    tink::aead::aead_key_templates
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_eax_key_manager
    tink::aead::aes_gcm_key_manager
    tink::aead::aes_gcm_siv_key_manager
    tink::aead::xchacha20_poly1305_key_manager
    tink::internal::configuration_impl
    tink::internal::key_gen_configuration_impl
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper_store
    tink::internal::ssl_util
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)
