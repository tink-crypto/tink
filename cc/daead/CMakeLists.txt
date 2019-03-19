tink_module(daead)

tink_cc_library(
  NAME aes_siv_key_manager
  SRCS
    aes_siv_key_manager.cc
    aes_siv_key_manager.h
  DEPS
    tink::core::aead
    tink::core::key_manager
    tink::core::key_manager_base
    tink::subtle::aes_siv_boringssl
    tink::subtle::random
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::aes_siv_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    absl::base
)

tink_cc_library(
  NAME deterministic_aead_wrapper
  SRCS
    deterministic_aead_wrapper.cc
    deterministic_aead_wrapper.h
  DEPS
    tink::core::crypto_format
    tink::core::deterministic_aead
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::subtle::subtle_util_boringssl
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
    absl::strings
)

tink_cc_library(
  NAME deterministic_aead_catalogue
  SRCS
    deterministic_aead_catalogue.cc
    deterministic_aead_catalogue.h
  DEPS
    tink::daead::aes_siv_key_manager
    tink::core::catalogue
    tink::core::deterministic_aead
    tink::core::key_manager
    tink::util::status
    absl::memory
)

tink_cc_library(
  NAME deterministic_aead_config
  SRCS
    deterministic_aead_config.cc
    deterministic_aead_config.h
  DEPS
    tink::daead::deterministic_aead_catalogue
    tink::core::config
    tink::mac::mac_config
    tink::util::status
    tink::proto::config_cc_proto
    absl::memory
)

tink_cc_library(
  NAME deterministic_aead_factory
  SRCS
    deterministic_aead_factory.cc
    deterministic_aead_factory.h
  DEPS
    tink::daead::deterministic_aead_wrapper
    tink::core::deterministic_aead
    tink::core::key_manager
    tink::core::keyset_handle
    tink::core::primitive_set
    tink::core::registry
    tink::util::status
    tink::util::statusor
    absl::base
)

tink_cc_library(
  NAME deterministic_aead_key_templates
  SRCS
    deterministic_aead_key_templates.cc
    deterministic_aead_key_templates.h
  DEPS
    tink::proto::aes_siv_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)

# tests

tink_cc_test(
  NAME aes_siv_key_manager_test
  SRCS aes_siv_key_manager_test.cc
  DEPS
    tink::daead::aes_siv_key_manager
    tink::core::aead
    tink::util::status
    tink::util::statusor
    tink::proto::aes_eax_cc_proto
    tink::proto::aes_siv_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME deterministic_aead_wrapper_test
  SRCS deterministic_aead_wrapper_test.cc
  DEPS
    tink::daead::deterministic_aead_wrapper
    tink::core::deterministic_aead
    tink::core::primitive_set
    tink::util::status
    tink::util::test_util
    tink::proto::tink_cc_proto
    absl::memory
)

tink_cc_test(
  NAME deterministic_aead_catalogue_test
  SRCS deterministic_aead_catalogue_test.cc
  DEPS
    tink::daead::deterministic_aead_catalogue
    tink::daead::deterministic_aead_config
    tink::core::catalogue
    tink::core::deterministic_aead
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME deterministic_aead_config_test
  SRCS deterministic_aead_config_test.cc
  DEPS
    tink::daead::deterministic_aead_config
    tink::daead::deterministic_aead_key_templates
    tink::core::catalogue
    tink::core::config
    tink::core::deterministic_aead
    tink::core::keyset_handle
    tink::core::registry
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
    absl::memory
)

tink_cc_test(
  NAME deterministic_aead_factory_test
  SRCS deterministic_aead_factory_test.cc
  DEPS
    tink::daead::aes_siv_key_manager
    tink::daead::deterministic_aead_config
    tink::daead::deterministic_aead_factory
    tink::core::crypto_format
    tink::core::deterministic_aead
    tink::core::keyset_handle
    tink::util::test_keyset_handle
    tink::util::status
    tink::util::test_util
    tink::proto::aes_siv_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME deterministic_aead_key_templates_test
  SRCS deterministic_aead_key_templates_test.cc
  DEPS
    tink::daead::aes_siv_key_manager
    tink::daead::deterministic_aead_key_templates
    tink::proto::aes_siv_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)
