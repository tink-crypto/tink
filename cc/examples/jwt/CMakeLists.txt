add_executable(jwt_sign jwt_sign.cc)
target_include_directories(jwt_sign PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(jwt_sign
  tink::static
  tink::jwt::jwt_signature_config
  absl::check
  absl::flags_parse
  util)

add_executable(jwt_verify jwt_verify.cc)
target_include_directories(jwt_verify PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(jwt_verify
  tink::static
  tink::jwt::jwk_set_converter
  tink::jwt::jwt_signature_config
  absl::check
  absl::flags_parse
  util)

add_executable(jwt_generate_public_jwk_set jwt_generate_public_jwk_set.cc)
target_include_directories(jwt_generate_public_jwk_set PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(jwt_generate_public_jwk_set
  tink::static
  tink::jwt::jwk_set_converter
  tink::jwt::jwt_signature_config
  absl::check
  absl::flags_parse
  util)

add_test(
  NAME jwt_signature_cli_test
  COMMAND "${BASH_PROGRAM}"
    "${CMAKE_CURRENT_SOURCE_DIR}/jwt_signature_cli_test.sh"
    "${CMAKE_CURRENT_BINARY_DIR}/jwt_sign"
    "${CMAKE_CURRENT_BINARY_DIR}/jwt_generate_public_jwk_set"
    "${CMAKE_CURRENT_BINARY_DIR}/jwt_verify"
    "${CMAKE_CURRENT_SOURCE_DIR}/jwt_signature_private_keyset.json"
    "${CMAKE_CURRENT_SOURCE_DIR}/jwt_signature_public_keyset.json")
