tink_module(mac)

tink_cc_library(
  NAME mac_wrapper
  SRCS
    mac_wrapper.cc
    mac_wrapper.h
  DEPS
    tink::core::crypto_format
    tink::core::mac
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::subtle::subtle_util_boringssl
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME mac_config
  SRCS
    mac_config.cc
    mac_config.h
  DEPS
    tink::mac::mac_catalogue
    tink::core::config
    tink::util::status
    tink::proto::config_cc_proto
    absl::memory
)

tink_cc_library(
  NAME mac_catalogue
  SRCS
    mac_catalogue.cc
    mac_catalogue.h
  DEPS
    tink::mac::hmac_key_manager
    tink::core::catalogue
    tink::util::status
)

tink_cc_library(
  NAME mac_factory
  SRCS
    mac_factory.cc
    mac_factory.h
  DEPS
    tink::mac::mac_wrapper
    tink::core::key_manager
    tink::core::keyset_handle
    tink::core::mac
    tink::core::primitive_set
    tink::core::registry
    tink::util::status
    tink::util::statusor
    absl::base
)

tink_cc_library(
  NAME mac_key_templates
  SRCS
    mac_key_templates.cc
    mac_key_templates.h
  DEPS
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME hmac_key_manager
  SRCS
    hmac_key_manager.cc
    hmac_key_manager.h
  DEPS
    tink::core::key_manager
    tink::core::key_manager_base
    tink::core::mac
    tink::subtle::hmac_boringssl
    tink::subtle::random
    tink::util::enums
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
    tink::proto::tink_cc_proto
)

# tests

tink_cc_test(
  NAME mac_wrapper_test
  SRCS mac_wrapper_test.cc
  DEPS
    tink::mac::mac_wrapper
    tink::core::crypto_format
    tink::core::mac
    tink::core::primitive_set
    tink::util::status
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME mac_catalogue_test
  SRCS mac_catalogue_test.cc
  DEPS
    tink::mac::mac_catalogue
    tink::mac::mac_config
    tink::core::catalogue
    tink::core::config
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME mac_config_test
  SRCS mac_config_test.cc
  DEPS
    tink::mac::mac_config
    tink::mac::mac_key_templates
    tink::core::catalogue
    tink::core::config
    tink::core::keyset_handle
    tink::core::mac
    tink::core::registry
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME mac_factory_test
  SRCS mac_factory_test.cc
  DEPS
    tink::mac::mac_config
    tink::mac::mac_factory
    tink::mac::mac_wrapper
    tink::core::config
    tink::core::crypto_format
    tink::core::keyset_handle
    tink::core::mac
    tink::mac::hmac_key_manager
    tink::util::test_keyset_handle
    tink::util::status
    tink::util::test_util
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME mac_key_templates_test
  SRCS mac_key_templates_test.cc
  DEPS
    tink::mac::hmac_key_manager
    tink::mac::mac_key_templates
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME hmac_key_manager_test
  SRCS hmac_key_manager_test.cc
  DEPS
    tink::mac::hmac_key_manager
    tink::core::mac
    tink::util::status
    tink::util::statusor
    tink::proto::aes_ctr_cc_proto
    tink::proto::aes_ctr_hmac_aead_cc_proto
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
    tink::proto::tink_cc_proto
)
