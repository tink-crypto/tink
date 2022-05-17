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
r"""Creates the "BUILD.bazel" file on Kororo.

Usage: python3 create_main_build_file.py \
  java_dependencies_file.txt  \
  android_dependencies_file.txt \
  aws_kms_dependencies_file.txt \
  gcp_kms_dependencies_file.txt
where the files contain a list of dependencies to be used in the created file.
"""

import string
import sys

TEMPLATE = string.Template("""\
## This file is created using "create_main_build_file.py".

load("//tools:gen_maven_jar_rules.bzl", "gen_maven_jar_rules")
load("//tools:check_deps.bzl", "check_deps")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

exports_files(["BUILD"])

# Maven jars.
# DO NOT USE FOR ANY OTHER PURPOSES.

gen_maven_jar_rules(
    name = "tink",
    doctitle = "Tink Cryptography API",
    manifest_lines = [
        "Automatic-Module-Name: com.google.crypto.tink",
    ],
    root_packages = [
        "com.google.crypto.tink",
    ],
    deps = [
$java_deps_formatted
    ],
)

gen_maven_jar_rules(
    name = "tink-android",
    doctitle = "Tink Cryptography API for Android",
    resources = glob([
        "src/main/resources/**",
    ]),
    root_packages = [
        "com.google.crypto.tink",
    ],
    shaded_packages = [
        # The following package(s) will be shaded, according to the rules
        # specified in shading_rules.
        "com.google.protobuf",
    ],
    shading_rules = "jar_jar_rules.txt",
    deps = [
$andr_deps_formatted
    ],
)

gen_maven_jar_rules(
    name = "tink-awskms",
    doctitle = "Tink Cryptography API with AWS KMS",
    manifest_lines = [
        "Automatic-Module-Name: com.google.crypto.tink.integration.awskms",
    ],
    root_packages = [
        "com.google.crypto.tink",
    ],
    deps = [
$awsk_deps_formatted
    ],
)

gen_maven_jar_rules(
    name = "tink-gcpkms",
    doctitle = "Tink Cryptography API with Google Cloud KMS",
    manifest_lines = [
        "Automatic-Module-Name: com.google.crypto.tink.integration.gcpkms",
    ],
    root_packages = [
        "com.google.crypto.tink",
    ],
    deps = [
$gcpk_deps_formatted
    ],
)

# Check that tink-android depends on protobuf-lite, not the full version.
check_deps(
    name = "tink-android-dep-checks",
    disallowed_deps = ["@com_google_protobuf//java/core:core"],
    required_deps = ["@com_google_protobuf//java/lite:lite"],
    deps = [":tink-android-unshaded"],
)""")


def _format_deps(deps_list):
  """Maps a list of dependencies into a single string."""

  stripped_deps = [l.strip() for l in sorted(deps_list)]
  indented_quoted_deps = ['        "{}",'.format(l) for l in stripped_deps]
  return '\n'.join(indented_quoted_deps)


def main():
  if len(sys.argv) != 5:
    sys.exit('4 Arguments Required')

  with open(sys.argv[1], 'r') as f:
    java_deps_file_content = f.readlines()
  with open(sys.argv[2], 'r') as f:
    android_deps_file_content = f.readlines()
  with open(sys.argv[3], 'r') as f:
    aws_kms_deps_file_content = f.readlines()
  with open(sys.argv[4], 'r') as f:
    gcp_kms_deps_file_content = f.readlines()

  print(
      TEMPLATE.substitute(
          java_deps_formatted=_format_deps(java_deps_file_content),
          andr_deps_formatted=_format_deps(android_deps_file_content),
          awsk_deps_formatted=_format_deps(aws_kms_deps_file_content),
          gcpk_deps_formatted=_format_deps(gcp_kms_deps_file_content)))

if __name__ == '__main__':
  main()
