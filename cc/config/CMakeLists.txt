tink_module(config)

tink_cc_library(
  NAME tink_config
  SRCS
    tink_config.cc
    tink_config.h
  DEPS
    absl::core_headers
    tink::core::config
    tink::core::key_manager
    tink::core::registry
    tink::daead::deterministic_aead_config
    tink::hybrid::hybrid_config
    tink::prf::prf_config
    tink::signature::signature_config
    tink::streamingaead::streaming_aead_config
    tink::util::status
    tink::proto::config_cc_proto
)

tink_cc_library(
  NAME config_util
  SRCS
    config_util.cc
    config_util.h
  DEPS
    tink::proto::config_cc_proto
)

tink_cc_library(
  NAME tink_fips
  SRCS
    tink_fips.cc
    tink_fips.h
  DEPS
    absl::core_headers
    crypto
    tink::internal::fips_utils
    tink::internal::registry_impl
    tink::util::status
)

# tests

tink_cc_test(
  NAME tink_config_test
  SRCS
    tink_config_test.cc
  DEPS
    tink::config::tink_config
    gmock
    absl::status
    tink::core::cc
    tink::core::aead
    tink::core::config
    tink::core::deterministic_aead
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::core::mac
    tink::core::registry
    tink::core::streaming_aead
    tink::aead::aes_gcm_key_manager
    tink::util::status
    tink::util::test_matchers
)

tink_cc_test(
  NAME config_util_test
  SRCS
    config_util_test.cc
  DEPS
    tink::config::config_util
    gmock
)

tink_cc_test(
  NAME tink_fips_test
  SRCS
    tink_fips_test.cc
  DEPS
    tink::config::tink_fips
    gmock
    absl::status
    crypto
    tink::core::registry
    tink::aead::aead_config
    tink::internal::fips_utils
    tink::util::status
    tink::util::test_matchers
)
