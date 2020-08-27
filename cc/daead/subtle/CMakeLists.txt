tink_module(daead:subtle)

tink_cc_library(
  NAME aead_or_daead
  SRCS
    aead_or_daead.cc
    aead_or_daead.h
  DEPS
    tink::core::aead
    tink::core::deterministic_aead
    absl::memory
    absl::bind_front
    absl::variant
)

tink_cc_test(
  NAME aead_or_daead_test
  SRCS aead_or_daead_test.cc
  DEPS
    tink::daead::subtle::aead_or_daead
    tink::util::test_matchers
    tink::util::test_util
)
