tink_cc_library(
  NAME raw_kem_decapsulate
  SRCS
    raw_kem_decapsulate.h
  DEPS
    absl::string_view
    tink::core::restricted_data
    tink::util::statusor
)

tink_cc_library(
  NAME raw_kem_encapsulate
  SRCS
    raw_kem_encapsulate.h
  DEPS
    tink::core::restricted_data
    tink::util::statusor
)
