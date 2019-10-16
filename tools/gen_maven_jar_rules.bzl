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

""" Definition of gen_maven_jar_rules. """

load("//tools:java_single_jar.bzl", "java_single_jar")

_TINK_PACKAGES = [
    "com.google.crypto.tink",
]

def gen_maven_jar_rules(
        name,
        deps = [],
        root_packages = _TINK_PACKAGES):
    """
    Generates rules that generate Maven jars for a given package.

    Args:
      name: Given a name, this function generates 2 rules: a compiled package
        name.jar and a source package name-src.jar.
      deps: Dependencies given to the two rules
      root_packages: see java_single_jar
    """

    java_single_jar(
        name = name,
        deps = deps,
        root_packages = root_packages,
    )

    source_jar_name = name + "-src"
    java_single_jar(
        name = source_jar_name,
        deps = deps,
        root_packages = root_packages,
        source_jar = True,
    )
