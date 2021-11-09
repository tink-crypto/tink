tink_module(subtle::prf)

tink_cc_library(
  NAME streaming_prf
  SRCS streaming_prf.h
  DEPS tink::core::input_stream
)

tink_cc_library(
  NAME streaming_prf_wrapper
  SRCS
    streaming_prf_wrapper.cc
    streaming_prf_wrapper.h
  DEPS
    tink::subtle::prf::streaming_prf
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::util::statusor
    absl::status
    absl::strings
)

tink_cc_library(
  NAME hkdf_streaming_prf
  SRCS
    hkdf_streaming_prf.cc
    hkdf_streaming_prf.h
  DEPS
    tink::subtle::prf::streaming_prf
    crypto
    tink::config::tink_fips
    tink::core::input_stream
    tink::internal::ssl_unique_ptr
    tink::subtle::subtle
    tink::subtle::subtle_util
    tink::subtle::subtle_util_boringssl
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    absl::memory
    absl::status
    absl::strings
)

tink_cc_library(
  NAME prf_set_util
  SRCS
    prf_set_util.cc
    prf_set_util.h
  DEPS
    tink::prf::prf_set
    tink::util::input_stream_util
    tink::util::status
    tink::util::statusor
    tink::subtle::mac::stateful_mac
    tink::subtle::prf::streaming_prf
    absl::strings
    absl::status
    absl::memory
)

tink_cc_test(
  NAME hkdf_streaming_prf_test
  SRCS hkdf_streaming_prf_test.cc
  DEPS
    tink::subtle::prf::hkdf_streaming_prf
    tink::subtle::prf::streaming_prf
    tink::subtle::subtle
    tink::config::tink_fips
    tink::util::input_stream_util
    tink::util::secret_data
    tink::util::test_matchers
    tink::util::test_util
    gmock
)

tink_cc_test(
  NAME streaming_prf_wrapper_test
  SRCS streaming_prf_wrapper_test.cc
  DEPS
    tink::subtle::prf::streaming_prf_wrapper
    tink::proto::tink_cc_proto
    tink::util::input_stream_util
    tink::util::istream_input_stream
    tink::util::test_matchers
    tink::util::test_util
    gmock
    absl::status
    absl::strings
)

tink_cc_test(
  NAME prf_set_util_test
  SRCS prf_set_util_test.cc
  DEPS
    tink::core::input_stream
    tink::util::istream_input_stream
    tink::util::status
    tink::util::test_matchers
    tink::subtle::prf::prf_set_util
    tink::subtle::prf::streaming_prf
    gmock
    absl::memory
    absl::status
    absl::strings
)
