tink_module(daead::subtle)

tink_cc_library(
  NAME aead_or_daead
  SRCS
    aead_or_daead.cc
    aead_or_daead.h
  DEPS
    absl::bind_front
    absl::string_view
    absl::variant
    tink::core::aead
    tink::core::deterministic_aead
    tink::util::statusor
)

tink_cc_test(
  NAME aead_or_daead_test
  SRCS
    aead_or_daead_test.cc
  DEPS
    tink::daead::subtle::aead_or_daead
    gmock
    absl::memory
    absl::status
    absl::string_view
    tink::core::aead
    tink::core::deterministic_aead
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
)
