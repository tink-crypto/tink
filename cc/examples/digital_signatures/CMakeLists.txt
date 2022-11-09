add_executable(digital_signatures_cli digital_signatures_cli.cc)
target_include_directories(digital_signatures_cli PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(digital_signatures_cli
  tink::static
  absl::flags_parse
  util)

add_test(
  NAME digital_signatures_cli_test
  COMMAND "${BASH_PROGRAM}"
    "${CMAKE_CURRENT_SOURCE_DIR}/digital_signatures_cli_test.sh"
    "${CMAKE_CURRENT_BINARY_DIR}/digital_signatures_cli"
    "${CMAKE_CURRENT_SOURCE_DIR}/digital_signature_private_keyset.json"
    "${CMAKE_CURRENT_SOURCE_DIR}/digital_signature_public_keyset.json")
