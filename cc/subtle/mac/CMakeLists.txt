tink_module(subtle::mac)

tink_cc_library(
  NAME stateful_mac
  SRCS
    stateful_mac.h
  DEPS
    absl::strings
    tink::util::status
    tink::util::statusor
)
