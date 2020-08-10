tink_module(mac)

tink_cc_library(
  NAME jwt_names
  SRCS
    jwt_names.cc
    jwt_names.h
  DEPS
    absl::strings
    absl::strings:str_format
    tink::util::status
    tink::util::statusor
)
