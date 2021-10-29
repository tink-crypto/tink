tink_module(prf)

tink_cc_library(
  NAME hkdf_prf_key_manager
  SRCS hkdf_prf_key_manager.h
  DEPS
    tink::core::key_type_manager
    tink::core::input_stream
    tink::core::key_type_manager
    tink::prf::prf_set
    tink::subtle::subtle
    tink::subtle::prf::hkdf_streaming_prf
    tink::subtle::prf::prf_set_util
    tink::subtle::prf::streaming_prf
    tink::util::constants
    tink::util::enums
    tink::util::input_stream_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::common_cc_proto
    tink::proto::hkdf_prf_cc_proto
    tink::proto::tink_cc_proto
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME prf_config
  SRCS
    prf_config.cc
    prf_config.h
  DEPS
    tink::prf::aes_cmac_prf_key_manager
    tink::prf::hkdf_prf_key_manager
    tink::prf::hmac_prf_key_manager
    tink::prf::prf_set_wrapper
    tink::config::tink_fips
    tink::core::registry
    tink::util::status
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME prf_key_templates
  SRCS
    prf_key_templates.h
    prf_key_templates.cc
  DEPS
    tink::prf::aes_cmac_prf_key_manager
    tink::prf::hmac_prf_key_manager
    tink::prf::hkdf_prf_key_manager
    tink::proto::aes_cmac_prf_cc_proto
    tink::proto::hkdf_prf_cc_proto
    tink::proto::hmac_prf_cc_proto
    tink::proto::tink_cc_proto
    absl::memory
)

tink_cc_library(
  NAME prf_set
  SRCS
    prf_set.h
    prf_set.cc
  DEPS
    tink::util::statusor
    absl::strings
)

tink_cc_library(
  NAME prf_set_wrapper
  SRCS
    prf_set_wrapper.cc
    prf_set_wrapper.h
  DEPS
    tink::prf::prf_set
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::proto::tink_cc_proto
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_cmac_prf_key_manager
  SRCS aes_cmac_prf_key_manager.h
  DEPS
    tink::core::key_type_manager
    tink::core::key_manager
    tink::proto::aes_cmac_prf_cc_proto
    tink::proto::tink_cc_proto
    tink::subtle::common_enums
    tink::subtle::random
    tink::subtle::stateful_cmac_boringssl
    tink::subtle::prf::prf_set_util
    tink::util::constants
    tink::util::errors
    tink::util::enums
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    absl::memory
    absl::strings
)

tink_cc_library(
  NAME hmac_prf_key_manager
  SRCS
    hmac_prf_key_manager.cc
    hmac_prf_key_manager.h
  DEPS
    tink::core::key_type_manager
    tink::core::key_manager
    tink::proto::hmac_prf_cc_proto
    tink::proto::tink_cc_proto
    tink::subtle::common_enums
    tink::subtle::random
    tink::subtle::stateful_hmac_boringssl
    tink::subtle::prf::prf_set_util
    tink::util::constants
    tink::util::errors
    tink::util::enums
    tink::util::input_stream_util
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    absl::memory
    absl::strings
)

tink_cc_test(
  NAME hkdf_prf_key_manager_test
  SRCS hkdf_prf_key_manager_test.cc
  DEPS
    tink::prf::hkdf_prf_key_manager
    tink::subtle::prf::hkdf_streaming_prf
    tink::subtle::prf::prf_set_util
    tink::subtle::prf::streaming_prf
    tink::subtle::subtle
    tink::util::input_stream_util
    tink::util::istream_input_stream
    tink::util::secret_data
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::common_cc_proto
    gmock
)

tink_cc_test(
  NAME prf_key_templates_test
  SRCS prf_key_templates_test.cc
  DEPS
    tink::prf::aes_cmac_prf_key_manager
    tink::prf::hmac_prf_key_manager
    tink::prf::hkdf_prf_key_manager
    tink::prf::prf_key_templates
    tink::proto::aes_cmac_prf_cc_proto
    tink::proto::hmac_prf_cc_proto
    tink::util::test_matchers
    absl::memory
    gmock
)

tink_cc_test(
  NAME prf_set_wrapper_test
  SRCS prf_set_wrapper_test.cc
  DEPS
    tink::prf::prf_set
    tink::prf::prf_set_wrapper
    tink::util::statusor
    tink::util::test_matchers
    absl::memory
    absl::strings
    gmock
)

tink_cc_test(
  NAME prf_set_test
  SRCS prf_set_test.cc
  DEPS
    tink::prf::prf_set
    tink::prf::prf_config
    tink::prf::prf_key_templates
    tink::core::keyset_handle
    tink::core::keyset_manager
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    absl::memory
    absl::strings
    gmock
)

tink_cc_test(
  NAME aes_cmac_prf_key_manager_test
  SRCS aes_cmac_prf_key_manager_test.cc
  DEPS
    tink::prf::aes_cmac_prf_key_manager
    tink::proto::aes_cmac_prf_cc_proto
    tink::subtle::aes_cmac_boringssl
    tink::util::istream_input_stream
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    gmock
)

tink_cc_test(
  NAME hmac_prf_key_manager_test
  SRCS hmac_prf_key_manager_test.cc
  DEPS
    tink::prf::hmac_prf_key_manager
    tink::prf::prf_set
    tink::core::key_manager_impl
    tink::proto::hmac_prf_cc_proto
    tink::subtle::hmac_boringssl
    tink::util::istream_input_stream
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    gmock
)

tink_cc_test(
  NAME prf_config_test
  SRCS prf_config_test.cc
  DEPS
    tink::prf::hmac_prf_key_manager
    tink::prf::prf_config
    tink::prf::prf_key_templates
    tink::prf::prf_set
    tink::core::config
    tink::core::registry
    tink::config::tink_fips
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
    absl::status
    gmock
)
