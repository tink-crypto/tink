tink_module(subtle::prf)

tink_cc_library(
  NAME streaming_prf
  SRCS streaming_prf.h
  DEPS tink::core::input_stream
)
