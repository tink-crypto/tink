tink_module(prf)

tink_cc_library(
  NAME hkdf_prf_key_manager
  SRCS hkdf_prf_key_manager.h
  DEPS
    tink::core::key_type_manager
    tink::core::input_stream
    tink::core::key_type_manager
    tink::subtle::subtle
    tink::subtle_prf::hkdf_streaming_prf
    tink::subtle_prf::streaming_prf
    tink::util::constants
    tink::util::enums
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::common_cc_proto
    tink::proto::hkdf_prf_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME hkdf_prf_key_manager_test
  SRCS hkdf_prf_key_manager_test.cc
  DEPS
    tink::prf::hkdf_prf_key_manager
    tink::subtle_prf::hkdf_streaming_prf
    tink::subtle_prf::streaming_prf
    tink::subtle::subtle
    tink::util::input_stream_util
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::common_cc_proto
    gmock
)
