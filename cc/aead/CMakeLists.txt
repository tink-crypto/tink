tink_module(aead)

tink_cc_library(
  NAME aead_wrapper
  SRCS
    aead_wrapper.cc
    aead_wrapper.h
  DEPS
    tink::core::aead
    tink::core::crypto_format
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::core::registry
    tink::subtle::subtle_util_boringssl
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
    absl::strings
)

tink_cc_library(
  NAME aead_catalogue
  SRCS
    aead_catalogue.cc
    aead_catalogue.h
  DEPS
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_eax_key_manager
    tink::aead::aes_gcm_key_manager
    tink::aead::xchacha20_poly1305_key_manager
    tink::core::aead
    tink::core::catalogue
    tink::core::key_manager
    tink::util::status
)

tink_cc_library(
  NAME aead_config
  SRCS
    aead_config.cc
    aead_config.h
  DEPS
    tink::aead::aead_catalogue
    tink::aead::aead_wrapper
    tink::core::config
    tink::mac::mac_config
    tink::util::status
    tink::proto::config_cc_proto
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
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    tink::proto::xchacha20_poly1305_cc_proto
)

tink_cc_library(
  NAME aes_eax_key_manager
  SRCS
    aes_eax_key_manager.cc
    aes_eax_key_manager.h
  DEPS
    tink::core::aead
    tink::core::key_manager
    tink::core::key_manager_base
    tink::subtle::aes_eax_boringssl
    tink::subtle::random
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::aes_eax_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    absl::base
)

tink_cc_library(
  NAME aes_gcm_key_manager
  SRCS
    aes_gcm_key_manager.cc
    aes_gcm_key_manager.h
  DEPS
    tink::core::aead
    tink::core::key_manager
    tink::core::key_manager_base
    tink::subtle::aes_gcm_boringssl
    tink::subtle::random
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::aes_gcm_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    absl::base
)

tink_cc_library(
  NAME aes_ctr_hmac_aead_key_manager
  SRCS
    aes_ctr_hmac_aead_key_manager.cc
    aes_ctr_hmac_aead_key_manager.h
  DEPS
    tink::core::aead
    tink::core::key_manager
    tink::core::key_manager_base
    tink::core::mac
    tink::core::registry
    tink::subtle::aes_ctr_boringssl
    tink::subtle::encrypt_then_authenticate
    tink::subtle::hmac_boringssl
    tink::subtle::random
    tink::util::enums
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::aes_ctr_hmac_aead_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    absl::base
)

tink_cc_library(
  NAME xchacha20_poly1305_key_manager
  SRCS
    xchacha20_poly1305_key_manager.cc
    xchacha20_poly1305_key_manager.h
  DEPS
    tink::core::aead
    tink::core::key_manager
    tink::core::key_manager_base
    tink::subtle::random
    tink::subtle::xchacha20_poly1305_boringssl
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::empty_cc_proto
    tink::proto::tink_cc_proto
    tink::proto::xchacha20_poly1305_cc_proto
    absl::strings
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
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME aead_catalogue_test
  SRCS aead_catalogue_test.cc
  DEPS
    tink::aead::aead_catalogue
    tink::aead::aead_config
    tink::core::aead
    tink::core::catalogue
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME aead_config_test
  SRCS aead_config_test.cc
  DEPS
    tink::aead::aead_config
    tink::aead::aead_key_templates
    tink::core::aead
    tink::core::catalogue
    tink::core::config
    tink::core::keyset_handle
    tink::core::registry
    tink::util::status
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
    tink::aead::aead_key_templates
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_eax_key_manager
    tink::aead::aes_gcm_key_manager
    tink::aead::xchacha20_poly1305_key_manager
    tink::proto::aes_ctr_hmac_aead_cc_proto
    tink::proto::aes_eax_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    tink::proto::xchacha20_poly1305_cc_proto
)

tink_cc_test(
  NAME aes_eax_key_manager_test
  SRCS aes_eax_key_manager_test.cc
  DEPS
    tink::aead::aes_eax_key_manager
    tink::core::aead
    tink::util::status
    tink::util::statusor
    tink::proto::aes_eax_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME aes_gcm_key_manager_test
  SRCS aes_gcm_key_manager_test.cc
  DEPS
    tink::aead::aes_gcm_key_manager
    tink::core::aead
    tink::util::status
    tink::util::statusor
    tink::proto::aes_eax_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME aes_ctr_hmac_aead_key_manager_test
  SRCS aes_ctr_hmac_aead_key_manager_test.cc
  DEPS
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::core::config
    tink::mac::mac_config
    tink::util::status
    tink::util::statusor
    tink::proto::aes_ctr_hmac_aead_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME xchacha20_poly1305_key_manager_test
  SRCS xchacha20_poly1305_key_manager_test.cc
  DEPS
    tink::aead::xchacha20_poly1305_key_manager
    tink::core::aead
    tink::util::status
    tink::util::statusor
    tink::proto::aes_eax_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    tink::proto::xchacha20_poly1305_cc_proto
)
