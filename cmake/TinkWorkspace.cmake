# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Download, unpack and setup Tink dependencies.
#
# Despite the looks, http_archive rules are not purely declarative, and order
# matters. All variables defined before a rule are visible when configuring the
# dependency it declares, and the targets provided by a dependency are visible
# (only) after it has been declared. Following dependencies may rely on targets
# defined by a previous one, for instance on gtest or absl.
#
# Some rules imported from dependencies require small fixes, which are specified
# after the relative http_archive rule. Please always document the intended
# purpose of such statements, and why they are necessary.
#
# In general, when adding a new dependency you should follow this structure:
#
# <set any configuration variable, if any>
# <http_archive for your dependency>
# <define or fix newly imported targets, if any>
#
# Many projects provide switches to disable tests or examples, which you should
# specify, in order to speed up the compilation process.

include(HttpArchive)
include(TinkUtil)

# Creates an interface target from an imported one.
#
# Parameters:
#   INTERFACE_TARGET Name of the interface target.
#   IMPORTED_TARGET Name of the imported target (e.g., with find_package).
#
macro(_create_interface_target INTERFACE_TARGET IMPORTED_TARGET)
  add_library(${INTERFACE_TARGET} INTERFACE)
  target_link_libraries(${INTERFACE_TARGET} INTERFACE ${IMPORTED_TARGET})
  target_include_directories(${INTERFACE_TARGET} INTERFACE ${IMPORTED_TARGET})
endmacro()

set(gtest_force_shared_crt ON CACHE BOOL "Tink dependency override" FORCE)

if (NOT TINK_USE_INSTALLED_GOOGLETEST)
  http_archive(
    NAME com_google_googletest
    URL https://github.com/google/googletest/archive/refs/tags/release-1.11.0.tar.gz
    SHA256 b4870bf121ff7795ba20d20bcdd8627b8e088f2d1dab299a031c1034eddc93d5
  )
else()
  # This uses the CMake's FindGTest module; if successful, this call to
  # find_package generates the targets GTest::gmock, GTest::gtest and
  # GTest::gtest_main.
  find_package(GTest CONFIG REQUIRED)
  _create_interface_target(gmock GTest::gmock)
  _create_interface_target(gtest_main GTest::gtest_main)
endif()

if (NOT TINK_USE_INSTALLED_ABSEIL)
  # Commit from 2021-12-03
  http_archive(
    NAME com_google_absl
    URL https://github.com/abseil/abseil-cpp/archive/9336be04a242237cd41a525bedfcf3be1bb55377.zip
    SHA256 368be019fc8d69a566ac2cf7a75262d5ba8f6409e3ef3cdbcf0106bdeb32e91c
  )
else()
  # This is everything that needs to be done here. Abseil already defines its
  # targets, which gets linked in tink_cc_(library|test).
  find_package(absl REQUIRED)
endif()

http_archive(
  NAME wycheproof
  URL https://github.com/google/wycheproof/archive/d8ed1ba95ac4c551db67f410c06131c3bc00a97c.zip
  SHA256 eb1d558071acf1aa6d677d7f1cabec2328d1cf8381496c17185bd92b52ce7545
  DATA_ONLY
)

# Symlink the Wycheproof test data.
# Paths are hard-coded in tests, which expects wycheproof/ in this location.
add_directory_alias("${wycheproof_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/external/wycheproof")

if (NOT TINK_USE_SYSTEM_OPENSSL)
  http_archive(
    NAME boringssl
    URL https://github.com/google/boringssl/archive/88cdf7dd2dbce1ecb9057c183095103d83373abe.zip
    SHA256 24092815136f956069fcfa5172166ad4e025166ce6fe500420c9e3e3c4f3da38
    CMAKE_SUBDIR src
  )

  # BoringSSL targets do not carry include directory info, this fixes it.
  target_include_directories(crypto PUBLIC "${boringssl_SOURCE_DIR}/src/include")
else()
  # Support for ED25519 was added from 1.1.1.
  find_package(OpenSSL 1.1.1 REQUIRED)
  _create_interface_target(crypto OpenSSL::Crypto)
endif()

set(RAPIDJSON_BUILD_DOC OFF CACHE BOOL "Tink dependency override" FORCE)
set(RAPIDJSON_BUILD_EXAMPLES OFF CACHE BOOL "Tink dependency override" FORCE)
set(RAPIDJSON_BUILD_TESTS OFF CACHE BOOL "Tink dependency override" FORCE)

http_archive(
  NAME rapidjson
  URL https://github.com/Tencent/rapidjson/archive/v1.1.0.tar.gz
  SHA256 bf7ced29704a1e696fbccf2a2b4ea068e7774fa37f6d7dd4039d0787f8bed98e
)

# Rapidjson is a header-only library with no explicit target. Here we create one.
add_library(rapidjson INTERFACE)
target_include_directories(rapidjson INTERFACE "${rapidjson_SOURCE_DIR}")

set(protobuf_BUILD_TESTS OFF CACHE BOOL "Tink dependency override" FORCE)
set(protobuf_BUILD_EXAMPLES OFF CACHE BOOL "Tink dependency override" FORCE)

http_archive(
  NAME com_google_protobuf
  URL https://github.com/protocolbuffers/protobuf/archive/v3.19.3.zip
  SHA256 6b6bf5cd8d0cca442745c4c3c9f527c83ad6ef35a405f64db5215889ac779b42
  CMAKE_SUBDIR cmake
)
