add_executable(jwt_signature_cli jwt_signature_cli.cc)
target_include_directories(jwt_signature_cli PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(jwt_signature_cli
  tink::static
  tink::jwt::jwt_signature_config
  absl::flags_parse
  util)

add_test(
  NAME jwt_signature_cli_test
  COMMAND "${BASH_PROGRAM}"
    "${CMAKE_CURRENT_SOURCE_DIR}/jwt_signature_cli_test.sh"
    "${CMAKE_CURRENT_BINARY_DIR}/jwt_signature_cli"
    "${CMAKE_CURRENT_SOURCE_DIR}/jwt_signature_private_keyset.json"
    "${CMAKE_CURRENT_SOURCE_DIR}/jwt_signature_public_keyset.json")
