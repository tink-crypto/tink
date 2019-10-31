tink_module(subtle_prf)

tink_cc_library(
  NAME streaming_prf
  SRCS streaming_prf.h
  DEPS tink::core::input_stream
)

tink_cc_library(
  NAME hkdf_streaming_prf
  SRCS
    hkdf_streaming_prf.cc
    hkdf_streaming_prf.h
  DEPS
    tink::subtle_prf::streaming_prf
    crypto
    tink::core::input_stream
    tink::subtle::subtle
    tink::subtle::subtle_util
    tink::subtle::subtle_util_boringssl
    absl::memory
    absl::strings
)

tink_cc_test(
  NAME hkdf_streaming_prf_test
  SRCS hkdf_streaming_prf_test.cc
  DEPS
    tink::subtle_prf::hkdf_streaming_prf
    tink::subtle_prf::streaming_prf
    tink::subtle::subtle
    tink::util::input_stream_util
    tink::util::test_matchers
    tink::util::test_util
    gmock
)
