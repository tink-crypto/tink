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
    tink::internal::monitoring_util
    tink::internal::registry_impl
    tink::internal::util
    tink::monitoring::monitoring
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
    tink::internal::monitoring_util
    tink::internal::registry_impl
    tink::internal::util
    tink::monitoring::monitoring
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
    absl::statusor
    absl::strings
    tink::core::aead
    tink::core::deterministic_aead
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::daead::subtle::aead_or_daead
    tink::subtle::aes_gcm_boringssl
    tink::subtle::aes_siv_boringssl
    tink::subtle::xchacha20_poly1305_boringssl
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::statusor
    tink::proto::aes_ctr_cc_proto
    tink::proto::aes_ctr_hmac_aead_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::aes_siv_cc_proto
    tink::proto::common_cc_proto
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

tink_cc_library(
  NAME hybrid_parameters
  SRCS
    hybrid_parameters.h
  DEPS
    tink::core::parameters
)

tink_cc_library(
  NAME hybrid_public_key
  SRCS
    hybrid_public_key.h
  DEPS
    tink::hybrid::hybrid_parameters
    absl::strings
    tink::core::key
)

tink_cc_library(
  NAME hybrid_private_key
  SRCS
    hybrid_private_key.h
  DEPS
    tink::hybrid::hybrid_parameters
    tink::hybrid::hybrid_public_key
    absl::strings
    tink::core::key
    tink::core::private_key
)

tink_cc_library(
  NAME hpke_parameters
  SRCS
    hpke_parameters.cc
    hpke_parameters.h
  DEPS
    tink::hybrid::hybrid_parameters
    absl::status
    tink::core::parameters
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hpke_public_key
  SRCS
    hpke_public_key.cc
    hpke_public_key.h
  DEPS
    tink::hybrid::hpke_parameters
    tink::hybrid::hybrid_public_key
    absl::status
    absl::strings
    absl::str_format
    absl::optional
    tink::core::key
    tink::core::partial_key_access_token
    tink::internal::ec_util
    tink::subtle::common_enums
    tink::subtle::subtle_util
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hpke_private_key
  SRCS
    hpke_private_key.cc
    hpke_private_key.h
  DEPS
    tink::hybrid::hpke_parameters
    tink::hybrid::hpke_public_key
    tink::hybrid::hybrid_private_key
    absl::status
    absl::strings
    absl::str_format
    crypto
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::partial_key_access_token
    tink::core::restricted_data
    tink::internal::bn_util
    tink::internal::ec_util
    tink::internal::err_util
    tink::internal::ssl_unique_ptr
    tink::subtle::common_enums
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hpke_proto_serialization
  SRCS
    hpke_proto_serialization.cc
    hpke_proto_serialization.h
  DEPS
    tink::hybrid::hpke_parameters
    absl::core_headers
    absl::status
    absl::strings
    tink::internal::mutable_serialization_registry
    tink::internal::parameters_parser
    tink::internal::parameters_serializer
    tink::internal::proto_parameters_serialization
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
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
    crypto
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::core::keyset_handle
    tink::core::registry
    tink::internal::fips_utils
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
    tink::hybrid::failing_hybrid
    tink::hybrid::hybrid_decrypt_wrapper
    gmock
    absl::strings
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::core::primitive_set
    tink::internal::registry_impl
    tink::monitoring::monitoring
    tink::monitoring::monitoring_client_mocks
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
    tink::hybrid::failing_hybrid
    tink::hybrid::hybrid_encrypt_wrapper
    gmock
    absl::status
    tink::core::hybrid_encrypt
    tink::core::primitive_set
    tink::internal::registry_impl
    tink::monitoring::monitoring
    tink::monitoring::monitoring_client_mocks
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

tink_cc_test(
  NAME hpke_parameters_test
  SRCS
    hpke_parameters_test.cc
  DEPS
    tink::hybrid::hpke_parameters
    gmock
    absl::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME hpke_public_key_test
  SRCS
    hpke_public_key_test.cc
  DEPS
    tink::hybrid::hpke_parameters
    tink::hybrid::hpke_public_key
    gmock
    absl::status
    absl::strings
    absl::optional
    crypto
    tink::core::partial_key_access
    tink::internal::ec_util
    tink::internal::ssl_unique_ptr
    tink::subtle::common_enums
    tink::subtle::random
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME hpke_private_key_test
  SRCS
    hpke_private_key_test.cc
  DEPS
    tink::hybrid::hpke_parameters
    tink::hybrid::hpke_private_key
    tink::hybrid::hpke_public_key
    gmock
    absl::status
    absl::strings
    absl::string_view
    absl::optional
    crypto
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::internal::ec_util
    tink::internal::ssl_unique_ptr
    tink::subtle::common_enums
    tink::subtle::random
    tink::util::secret_data
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME hpke_proto_serialization_test
  SRCS
    hpke_proto_serialization_test.cc
  DEPS
    tink::hybrid::hpke_parameters
    tink::hybrid::hpke_proto_serialization
    gmock
    absl::status
    absl::string_view
    absl::optional
    tink::core::parameters
    tink::internal::mutable_serialization_registry
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::hpke_cc_proto
    tink::proto::tink_cc_proto
)
