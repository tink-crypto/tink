tink_module(aead)

add_subdirectory(internal)

tink_cc_library(
  NAME aead_wrapper
  SRCS
    aead_wrapper.cc
    aead_wrapper.h
  DEPS
    absl::strings
    tink::core::aead
    tink::core::crypto_format
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::internal::util
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME cord_aead
  SRCS cord_aead.h
  DEPS
    tink::util::statusor
    absl::strings
    absl::cord
)

tink_cc_library(
  NAME cord_aead_wrapper
  SRCS
    cord_aead_wrapper.cc
    cord_aead_wrapper.h
  DEPS
    absl::strings
    absl::cord
    tink::aead::cord_aead
    tink::core::crypto_format
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::core::registry
    tink::subtle::subtle_util_boringssl
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME aead_config
  SRCS
    aead_config.cc
    aead_config.h
  DEPS
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_eax_key_manager
    tink::aead::aes_gcm_key_manager
    tink::aead::aes_gcm_siv_key_manager
    tink::aead::kms_aead_key_manager
    tink::aead::kms_envelope_aead_key_manager
    tink::aead::xchacha20_poly1305_key_manager
    tink::aead::aead_wrapper
    tink::config::config_util
    tink::config::tink_fips
    tink::mac::mac_config
    tink::util::status
    tink::proto::config_cc_proto
    absl::base
    absl::memory
)

tink_cc_library(
  NAME aead_factory
  SRCS
    aead_factory.cc
    aead_factory.h
  DEPS
    tink::aead::aead_wrapper
    tink::core::aead
    tink::core::key_manager
    tink::core::keyset_handle
    tink::core::primitive_set
    tink::core::registry
    tink::util::status
    tink::util::statusor
    absl::base
)

tink_cc_library(
  NAME aead_key_templates
  SRCS
    aead_key_templates.cc
    aead_key_templates.h
  DEPS
    tink::proto::aes_ctr_hmac_aead_cc_proto
    tink::proto::aes_eax_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::aes_gcm_siv_cc_proto
    tink::proto::common_cc_proto
    tink::proto::kms_envelope_cc_proto
    tink::proto::tink_cc_proto
    tink::proto::xchacha20_poly1305_cc_proto
    absl::strings
)

tink_cc_library(
  NAME aes_eax_key_manager
  SRCS
    aes_eax_key_manager.h
  DEPS
    tink::core::aead
    tink::core::key_type_manager
    tink::subtle::aes_eax_boringssl
    tink::subtle::random
    tink::util::constants
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::aes_eax_cc_proto
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME aes_gcm_key_manager
  SRCS
    aes_gcm_key_manager.h
  DEPS
    tink::aead::cord_aead
    tink::aead::internal::cord_aes_gcm_boringssl
    tink::core::aead
    tink::core::key_manager
    tink::core::key_type_manager
    tink::subtle::aes_gcm_boringssl
    tink::subtle::random
    tink::util::constants
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::input_stream_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::aes_gcm_cc_proto
    tink::proto::tink_cc_proto
    absl::base
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME aes_gcm_siv_key_manager
  SRCS
    aes_gcm_siv_key_manager.h
  DEPS
    tink::core::aead
    tink::core::key_manager
    tink::subtle::aes_gcm_siv_boringssl
    tink::subtle::random
    tink::util::constants
    tink::util::input_stream_util
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::aes_gcm_siv_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    absl::base
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME aes_ctr_hmac_aead_key_manager
  SRCS
    aes_ctr_hmac_aead_key_manager.cc
    aes_ctr_hmac_aead_key_manager.h
  DEPS
    tink::core::aead
    tink::core::key_type_manager
    tink::core::mac
    tink::core::registry
    tink::mac::hmac_key_manager
    tink::subtle::aes_ctr_boringssl
    tink::subtle::encrypt_then_authenticate
    tink::subtle::hmac_boringssl
    tink::subtle::random
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::aes_ctr_hmac_aead_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    absl::base
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME xchacha20_poly1305_key_manager
  SRCS
    xchacha20_poly1305_key_manager.h
  DEPS
    tink::core::aead
    tink::core::key_type_manager
    tink::subtle::random
    tink::subtle::xchacha20_poly1305_boringssl
    tink::util::errors
    tink::util::input_stream_util
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::xchacha20_poly1305_cc_proto
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME kms_aead_key_manager
  SRCS
    kms_aead_key_manager.h
  DEPS
    tink::core::aead
    tink::core::key_type_manager
    tink::core::kms_clients
    tink::util::constants
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::kms_aead_cc_proto
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME kms_envelope_aead
  SRCS
    kms_envelope_aead.cc
    kms_envelope_aead.h
  DEPS
    tink::core::aead
    tink::core::registry
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
    absl::strings
    absl::base
)

tink_cc_library(
  NAME kms_envelope_aead_key_manager
  SRCS
    kms_envelope_aead_key_manager.cc
    kms_envelope_aead_key_manager.h
  DEPS
    absl::memory
    absl::strings
    tink::core::aead
    tink::core::key_type_manager
    tink::core::kms_client
    tink::core::kms_clients
    tink::aead::kms_envelope_aead
    tink::util::constants
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::kms_envelope_cc_proto
)

tink_cc_library(
  NAME mock_aead
  SRCS mock_aead.h
  DEPS
    tink::core::aead
    gmock
)

# tests

tink_cc_test(
  NAME aead_wrapper_test
  SRCS aead_wrapper_test.cc
  DEPS
    tink::aead::aead_wrapper
    tink::core::aead
    tink::core::primitive_set
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME aead_config_test
  SRCS aead_config_test.cc
  DEPS
    absl::status
    tink::aead::aead_config
    tink::aead::aead_key_templates
    tink::aead::aes_gcm_key_manager
    tink::core::aead
    tink::core::config
    tink::core::keyset_handle
    tink::core::registry
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME aead_factory_test
  SRCS aead_factory_test.cc
  DEPS
    tink::aead::aead_config
    tink::aead::aead_factory
    tink::aead::aes_gcm_key_manager
    tink::core::aead
    tink::core::crypto_format
    tink::core::keyset_handle
    tink::util::test_keyset_handle
    tink::util::status
    tink::util::test_util
    tink::proto::aes_gcm_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME aead_key_templates_test
  SRCS aead_key_templates_test.cc
  DEPS
    tink::aead::aead_config
    tink::aead::aead_key_templates
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_eax_key_manager
    tink::aead::aes_gcm_key_manager
    tink::aead::aes_gcm_siv_key_manager
    tink::aead::kms_envelope_aead
    tink::aead::kms_envelope_aead_key_manager
    tink::aead::xchacha20_poly1305_key_manager
    tink::core::key_manager_impl
    tink::core::aead
    tink::core::keyset_handle
    tink::subtle::aead_test_util
    tink::util::fake_kms_client
    tink::util::test_matchers
    tink::proto::aes_ctr_hmac_aead_cc_proto
    tink::proto::aes_eax_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::aes_gcm_siv_cc_proto
    tink::proto::common_cc_proto
    tink::proto::kms_envelope_cc_proto
    tink::proto::tink_cc_proto
    tink::proto::xchacha20_poly1305_cc_proto
)

tink_cc_test(
  NAME aes_eax_key_manager_test
  SRCS aes_eax_key_manager_test.cc
  DEPS
    tink::aead::aes_eax_key_manager
    tink::core::aead
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::subtle::aead_test_util
    tink::proto::aes_eax_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    gmock
)

tink_cc_test(
  NAME aes_gcm_key_manager_test
  SRCS aes_gcm_key_manager_test.cc
  DEPS
    tink::aead::aes_gcm_key_manager
    tink::aead::cord_aead
    tink::aead::internal::cord_aes_gcm_boringssl
    tink::core::aead
    tink::subtle::aead_test_util
    tink::util::istream_input_stream
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::aes_gcm_cc_proto
    gmock
)

tink_cc_test(
  NAME aes_gcm_siv_key_manager_test
  SRCS aes_gcm_siv_key_manager_test.cc
  DEPS
    tink::aead::aes_gcm_siv_key_manager
    tink::core::key_type_manager
    tink::subtle::aead_test_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::aes_gcm_siv_cc_proto
)

tink_cc_test(
  NAME aes_ctr_hmac_aead_key_manager_test
  SRCS aes_ctr_hmac_aead_key_manager_test.cc
  DEPS
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::core::config
    tink::mac::mac_config
    tink::proto::aes_ctr_hmac_aead_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    tink::subtle::aead_test_util
    tink::subtle::aes_ctr_boringssl
    tink::util::enums
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME xchacha20_poly1305_key_manager_test
  SRCS xchacha20_poly1305_key_manager_test.cc
  DEPS
    tink::aead::xchacha20_poly1305_key_manager
    tink::core::aead
    tink::core::key_manager_impl
    tink::subtle::aead_test_util
    tink::util::istream_input_stream
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::xchacha20_poly1305_cc_proto
    gmock
)

tink_cc_test(
  NAME kms_aead_key_manager_test
  SRCS kms_aead_key_manager_test.cc
  DEPS
    tink::aead::kms_aead_key_manager
    tink::core::aead
    tink::core::kms_client
    tink::core::kms_clients
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::subtle::aead_test_util
    tink::proto::kms_aead_cc_proto
    gmock
)

tink_cc_test(
  NAME kms_envelope_aead_test
  SRCS kms_envelope_aead_test.cc
  DEPS
    absl::base
    absl::memory
    absl::status
    absl::strings
    tink::aead::aead_config
    tink::aead::aead_key_templates
    tink::aead::kms_envelope_aead
    tink::core::aead
    tink::core::registry
    tink::mac::mac_key_templates
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME kms_envelope_aead_key_manager_test
  SRCS kms_envelope_aead_key_manager_test.cc
  DEPS
    tink::aead::aead_config
    tink::aead::aead_key_templates
    tink::aead::aes_eax_key_manager
    tink::aead::kms_envelope_aead
    tink::aead::kms_envelope_aead_key_manager
    tink::core::aead
    tink::core::kms_client
    tink::core::kms_clients
    tink::core::registry
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::subtle::aead_test_util
    tink::proto::aes_eax_cc_proto
    tink::proto::kms_envelope_cc_proto
    tink::proto::tink_cc_proto
    gmock
)
