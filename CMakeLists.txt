cmake_minimum_required(VERSION 3.5)
project(Tink CXX)

# Deviate from the naming convention for consistency with tink_version.bzl.
include(tink_version.cmake)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(TINK_BUILD_TESTS "Build Tink tests" OFF)
option(TINK_USE_SYSTEM_OPENSSL "Build Tink linking to OpenSSL installed in the system" OFF)

set(CPACK_GENERATOR TGZ)
set(CPACK_PACKAGE_VERSION ${TINK_VERSION_LABEL})

include(CPack)
include(TinkWorkspace)
include(TinkBuildRules)
include(TinkUtil)

# Bazel rewrites import paths so that "cc/example/foo.h" can be included as
# "tink/example/foo.h". The following lines simulate this behaviour by creating
# a symlink to cc/ called tink/, and placing it in a separate subdirectory,
# which is then specified as a global include path.
#
# It's important to create a separate directory and not just drop the link in
# CMAKE_CURRENT_BINARY_DIR, since adding that to the include paths will
# make the whole contents of that directory visible to the compiled files,
# which may result in undeclared dependencies that nevertheless happen to work.
#
set(TINK_INCLUDE_ALIAS_DIR "${CMAKE_CURRENT_BINARY_DIR}/__include_alias")
add_directory_alias(
  "${CMAKE_CURRENT_SOURCE_DIR}/cc" "${TINK_INCLUDE_ALIAS_DIR}/tink")
list(APPEND TINK_INCLUDE_DIRS "${TINK_INCLUDE_ALIAS_DIR}")

add_subdirectory(cc)
add_subdirectory(proto)
