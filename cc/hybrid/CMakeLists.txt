tink_module(hybrid)

add_subdirectory(internal)

tink_cc_library(
  NAME hybrid_config
  SRCS
    hybrid_config.cc
    hybrid_config.h
  DEPS
    tink::hybrid::ecies_aead_hkdf_private_key_manager
    tink::hybrid::ecies_aead_hkdf_public_key_manager
    tink::hybrid::hybrid_decrypt_wrapper
    tink::hybrid::hybrid_encrypt_wrapper
    absl::core_headers
    absl::memory
    tink::core::registry
    tink::aead::aead_config
    tink::config::config_util
    tink::config::tink_fips
    tink::util::status
    tink::proto::config_cc_proto
)

tink_cc_library(
  NAME hpke_config
  SRCS
    hpke_config.cc
    hpke_config.h
  DEPS
    tink::hybrid::hybrid_decrypt_wrapper
    tink::hybrid::hybrid_encrypt_wrapper
    tink::core::registry
    tink::aead::aead_config
    tink::config::tink_fips
    tink::hybrid::internal::hpke_private_key_manager
    tink::hybrid::internal::hpke_public_key_manager
    tink::util::status
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hybrid_decrypt_wrapper
  SRCS
    hybrid_decrypt_wrapper.cc
    hybrid_decrypt_wrapper.h
  DEPS
    absl::status
    absl::strings
    tink::core::crypto_format
    tink::core::hybrid_decrypt
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::internal::util
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME hybrid_encrypt_wrapper
  SRCS
    hybrid_encrypt_wrapper.cc
    hybrid_encrypt_wrapper.h
  DEPS
    absl::status
    absl::strings
    tink::core::crypto_format
    tink::core::hybrid_encrypt
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::internal::util
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME hybrid_decrypt_factory
  SRCS
    hybrid_decrypt_factory.cc
    hybrid_decrypt_factory.h
  DEPS
    tink::hybrid::hybrid_decrypt_wrapper
    absl::core_headers
    tink::core::hybrid_decrypt
    tink::core::key_manager
    tink::core::keyset_handle
    tink::core::registry
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hybrid_encrypt_factory
  SRCS
    hybrid_encrypt_factory.cc
    hybrid_encrypt_factory.h
  DEPS
    tink::hybrid::hybrid_encrypt_wrapper
    absl::core_headers
    tink::core::hybrid_encrypt
    tink::core::key_manager
    tink::core::keyset_handle
    tink::core::registry
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hybrid_key_templates
  SRCS
    hybrid_key_templates.cc
    hybrid_key_templates.h
  DEPS
    absl::strings
    tink::aead::aead_key_templates
    tink::daead::deterministic_aead_key_templates
    tink::proto::common_cc_proto
    tink::proto::ecies_aead_hkdf_cc_proto
    tink::proto::hpke_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME ecies_aead_hkdf_dem_helper
  SRCS
    ecies_aead_hkdf_dem_helper.cc
    ecies_aead_hkdf_dem_helper.h
  DEPS
    absl::memory
    absl::status
    tink::core::aead
    tink::core::deterministic_aead
    tink::core::key_manager
    tink::core::registry
    tink::daead::subtle::aead_or_daead
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::statusor
    tink::proto::aes_ctr_cc_proto
    tink::proto::aes_ctr_hmac_aead_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::aes_siv_cc_proto
    tink::proto::hmac_cc_proto
    tink::proto::tink_cc_proto
    tink::proto::xchacha20_poly1305_cc_proto
)

tink_cc_library(
  NAME ecies_aead_hkdf_hybrid_decrypt
  SRCS
    ecies_aead_hkdf_hybrid_decrypt.cc
    ecies_aead_hkdf_hybrid_decrypt.h
  DEPS
    tink::hybrid::ecies_aead_hkdf_dem_helper
    absl::memory
    absl::status
    tink::core::hybrid_decrypt
    tink::internal::ec_util
    tink::subtle::ecies_hkdf_recipient_kem_boringssl
    tink::util::enums
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::proto::ecies_aead_hkdf_cc_proto
)

tink_cc_library(
  NAME ecies_aead_hkdf_hybrid_encrypt
  SRCS
    ecies_aead_hkdf_hybrid_encrypt.cc
    ecies_aead_hkdf_hybrid_encrypt.h
  DEPS
    tink::hybrid::ecies_aead_hkdf_dem_helper
    absl::memory
    absl::status
    absl::strings
    tink::core::aead
    tink::core::hybrid_encrypt
    tink::subtle::ecies_hkdf_sender_kem_boringssl
    tink::util::enums
    tink::util::status
    tink::util::statusor
    tink::proto::ecies_aead_hkdf_cc_proto
)

tink_cc_library(
  NAME ecies_aead_hkdf_private_key_manager
  SRCS
    ecies_aead_hkdf_private_key_manager.cc
    ecies_aead_hkdf_private_key_manager.h
  DEPS
    tink::hybrid::ecies_aead_hkdf_hybrid_decrypt
    tink::hybrid::ecies_aead_hkdf_public_key_manager
    absl::memory
    absl::status
    absl::strings
    tink::core::key_type_manager
    tink::core::private_key_type_manager
    tink::core::hybrid_decrypt
    tink::core::key_manager
    tink::internal::ec_util
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::ecies_aead_hkdf_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME ecies_aead_hkdf_public_key_manager
  SRCS
    ecies_aead_hkdf_public_key_manager.cc
    ecies_aead_hkdf_public_key_manager.h
  DEPS
    tink::hybrid::ecies_aead_hkdf_hybrid_encrypt
    absl::memory
    absl::status
    absl::strings
    tink::core::key_type_manager
    tink::core::hybrid_encrypt
    tink::core::key_manager
    tink::util::constants
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::common_cc_proto
    tink::proto::ecies_aead_hkdf_cc_proto
    tink::proto::tink_cc_proto
)

# tests

tink_cc_test(
  NAME hybrid_config_test
  SRCS
    hybrid_config_test.cc
  DEPS
    tink::hybrid::ecies_aead_hkdf_private_key_manager
    tink::hybrid::ecies_aead_hkdf_public_key_manager
    tink::hybrid::hybrid_config
    tink::hybrid::hybrid_key_templates
    gmock
    absl::status
    tink::core::config
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::core::keyset_handle
    tink::core::registry
    tink::config::tink_fips
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME hpke_config_test
  SRCS
    hpke_config_test.cc
  DEPS
    tink::hybrid::hpke_config
    tink::hybrid::hybrid_key_templates
    gmock
    absl::status
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::core::keyset_handle
    tink::core::registry
    tink::config::tink_fips
    tink::hybrid::internal::hpke_private_key_manager
    tink::hybrid::internal::hpke_public_key_manager
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME hybrid_decrypt_wrapper_test
  SRCS
    hybrid_decrypt_wrapper_test.cc
  DEPS
    tink::hybrid::hybrid_decrypt_wrapper
    gmock
    tink::core::hybrid_decrypt
    tink::core::primitive_set
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME hybrid_encrypt_wrapper_test
  SRCS
    hybrid_encrypt_wrapper_test.cc
  DEPS
    tink::hybrid::hybrid_encrypt_wrapper
    gmock
    tink::core::hybrid_encrypt
    tink::core::primitive_set
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME hybrid_decrypt_factory_test
  SRCS
    hybrid_decrypt_factory_test.cc
  DEPS
    tink::hybrid::ecies_aead_hkdf_public_key_manager
    tink::hybrid::hybrid_config
    tink::hybrid::hybrid_decrypt_factory
    gmock
    absl::memory
    tink::core::config
    tink::core::crypto_format
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::core::keyset_handle
    tink::util::status
    tink::util::test_keyset_handle
    tink::util::test_util
    tink::proto::ecies_aead_hkdf_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME hybrid_encrypt_factory_test
  SRCS
    hybrid_encrypt_factory_test.cc
  DEPS
    tink::hybrid::hybrid_config
    tink::hybrid::hybrid_encrypt_factory
    gmock
    tink::core::config
    tink::core::crypto_format
    tink::core::hybrid_encrypt
    tink::core::keyset_handle
    tink::util::status
    tink::util::test_keyset_handle
    tink::util::test_util
    tink::proto::ecies_aead_hkdf_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME hybrid_key_templates_test
  SRCS
    hybrid_key_templates_test.cc
  DEPS
    tink::hybrid::ecies_aead_hkdf_private_key_manager
    tink::hybrid::hybrid_config
    tink::hybrid::hybrid_key_templates
    gmock
    tink::aead::aead_key_templates
    tink::daead::deterministic_aead_key_templates
    tink::hybrid::internal::hpke_private_key_manager
    tink::util::test_matchers
    tink::proto::common_cc_proto
    tink::proto::ecies_aead_hkdf_cc_proto
    tink::proto::hpke_cc_proto
    tink::proto::tink_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME ecies_aead_hkdf_dem_helper_test
  SRCS
    ecies_aead_hkdf_dem_helper_test.cc
  DEPS
    tink::hybrid::ecies_aead_hkdf_dem_helper
    gmock
    absl::status
    tink::core::registry
    tink::aead::aes_gcm_key_manager
    tink::daead::aes_siv_key_manager
    tink::util::secret_data
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME ecies_aead_hkdf_hybrid_decrypt_test
  SRCS
    ecies_aead_hkdf_hybrid_decrypt_test.cc
  DEPS
    tink::hybrid::ecies_aead_hkdf_hybrid_decrypt
    tink::hybrid::ecies_aead_hkdf_hybrid_encrypt
    gmock
    absl::memory
    tink::core::hybrid_decrypt
    tink::core::registry
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_gcm_key_manager
    tink::aead::xchacha20_poly1305_key_manager
    tink::daead::aes_siv_key_manager
    tink::internal::ec_util
    tink::internal::ssl_util
    tink::subtle::random
    tink::util::enums
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_gcm_cc_proto
    tink::proto::common_cc_proto
    tink::proto::ecies_aead_hkdf_cc_proto
)

tink_cc_test(
  NAME ecies_aead_hkdf_hybrid_encrypt_test
  SRCS
    ecies_aead_hkdf_hybrid_encrypt_test.cc
  DEPS
    tink::hybrid::ecies_aead_hkdf_hybrid_encrypt
    gmock
    absl::memory
    tink::core::hybrid_encrypt
    tink::core::registry
    tink::aead::aes_gcm_key_manager
    tink::internal::ec_util
    tink::util::enums
    tink::util::statusor
    tink::util::test_util
    tink::proto::common_cc_proto
    tink::proto::ecies_aead_hkdf_cc_proto
)

tink_cc_test(
  NAME ecies_aead_hkdf_private_key_manager_test
  SRCS
    ecies_aead_hkdf_private_key_manager_test.cc
  DEPS
    tink::hybrid::ecies_aead_hkdf_private_key_manager
    tink::hybrid::ecies_aead_hkdf_public_key_manager
    tink::hybrid::hybrid_key_templates
    gmock
    absl::status
    tink::core::hybrid_decrypt
    tink::core::registry
    tink::aead::aead_key_templates
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_gcm_key_manager
    tink::subtle::hybrid_test_util
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_eax_cc_proto
    tink::proto::common_cc_proto
    tink::proto::ecies_aead_hkdf_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME ecies_aead_hkdf_public_key_manager_test
  SRCS
    ecies_aead_hkdf_public_key_manager_test.cc
  DEPS
    tink::hybrid::ecies_aead_hkdf_private_key_manager
    tink::hybrid::ecies_aead_hkdf_public_key_manager
    gmock
    absl::status
    tink::core::hybrid_encrypt
    tink::core::registry
    tink::aead::aead_key_templates
    tink::aead::aes_gcm_key_manager
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_eax_cc_proto
    tink::proto::common_cc_proto
    tink::proto::ecies_aead_hkdf_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME failing_hybrid
  SRCS
    failing_hybrid.cc
    failing_hybrid.h
  DEPS
    absl::strings
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
)

tink_cc_test(
  NAME failing_hybrid_test
  SRCS
    failing_hybrid_test.cc
  DEPS
    tink::hybrid::failing_hybrid
    gmock
    absl::status
    tink::util::test_matchers
)
