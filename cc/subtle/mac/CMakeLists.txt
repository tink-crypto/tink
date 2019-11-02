tink_module(subtle_mac)

tink_cc_library(
  NAME stateful_mac
  SRCS stateful_mac.h
  DEPS
    tink::util::status
    tink::util::statusor
)
