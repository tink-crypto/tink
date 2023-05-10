add_executable(hybrid_cli hybrid_cli.cc)
target_include_directories(hybrid_cli PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(hybrid_cli
  tink::static
  absl::check
  absl::flags_parse
  util)
# Tink CMake's configuration doesn't expose tink::core::hpke_config. Remove
# HPKE from this example when building with CMake.
target_compile_definitions(hybrid_cli PRIVATE TINK_EXAMPLES_EXCLUDE_HPKE)

add_test(
  NAME hybrid_cli_test
  COMMAND "${BASH_PROGRAM}"
    "${CMAKE_CURRENT_SOURCE_DIR}/hybrid_cli_test.sh"
    "${CMAKE_CURRENT_BINARY_DIR}/hybrid_cli"
    "${CMAKE_CURRENT_SOURCE_DIR}/testdata/hybrid_test_private_keyset.json"
    "${CMAKE_CURRENT_SOURCE_DIR}/testdata/hybrid_test_public_keyset.json")
