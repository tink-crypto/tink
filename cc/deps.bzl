# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Module extensions for tink."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def _abseil_impl(_ctx):
    http_archive(
        name = "com_google_absl",
        strip_prefix = "abseil-cpp-20230125.0",
        url = "https://github.com/abseil/abseil-cpp/archive/refs/tags/20230125.0.zip",
        sha256 = "70a2e30f715a7adcf5b7fcd2fcef7b624204b8e32ede8a23fd35ff5bd7d513b0",
    )

abseil_extension = module_extension(
    implementation = _abseil_impl,
)

def _boringssl_impl(_ctx):
    # Commit from 2022-02-25.
    http_archive(
        name = "boringssl",
        strip_prefix = "boringssl-d345d68d5c4b5471290ebe13f090f1fd5b7e8f58",
        url = "https://github.com/google/boringssl/archive/d345d68d5c4b5471290ebe13f090f1fd5b7e8f58.zip",
        sha256 = "482796f369c8655dbda3be801ae98c47916ecd3bff223d007a723fd5f5ecba22",
    )

boringssl_extension = module_extension(
    implementation = _boringssl_impl,
)

def _rapidjson_impl(_ctx):
    # Release from 2016-08-25 (still the latest release as of 2022-05-05).
    http_archive(
        name = "rapidjson",
        url = "https://github.com/Tencent/rapidjson/archive/v1.1.0.tar.gz",
        sha256 = "bf7ced29704a1e696fbccf2a2b4ea068e7774fa37f6d7dd4039d0787f8bed98e",
        strip_prefix = "rapidjson-1.1.0",
        build_file = "third_party/rapidjson.BUILD.bazel",
    )

rapidjson_extension = module_extension(
    implementation = _rapidjson_impl,
)

def _wycheproof_impl(_ctx):
    # Commit from 2019-12-17.
    http_archive(
        name = "wycheproof",
        strip_prefix = "wycheproof-d8ed1ba95ac4c551db67f410c06131c3bc00a97c",
        url = "https://github.com/google/wycheproof/archive/d8ed1ba95ac4c551db67f410c06131c3bc00a97c.zip",
        sha256 = "eb1d558071acf1aa6d677d7f1cabec2328d1cf8381496c17185bd92b52ce7545",
    )

wycheproof_extension = module_extension(
    implementation = _wycheproof_impl,
)
