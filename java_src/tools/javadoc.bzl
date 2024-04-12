# Copyright 2020 Google LLC
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

"""
Generates a Javadoc jar path/to/target/<name>.jar.

Arguments:
  srcs: source files to process. This might contain .java files or gen_rule that
      generates source jars.
  deps: targets that contain references to other types referenced in Javadoc. This can be the
      java_library/android_library target(s) for the same sources
  root_packages: Java packages to include in generated Javadoc. Any subpackages not listed in
      exclude_packages will be included as well
  exclude_packages: Java packages to exclude from generated Javadoc
  android_api_level: If Android APIs are used, the API level to compile against to generate
      Javadoc
  doctitle: title for Javadoc's index.html. See javadoc -doctitle
  bottom_text: text passed to javadoc's `-bottom` flag
  external_javadoc_links: a list of URLs that are passed to Javadoc's `-linkoffline` flag
"""

load("@rules_java//java:defs.bzl", "JavaInfo", "java_common")

def _check_non_empty(value, name):
    if not value:
        fail("%s must be non-empty" % name)

def _android_jar(android_api_level):
    if android_api_level == -1:
        return None
    return Label("@androidsdk//:platforms/android-%s/android.jar" % android_api_level)

def _javadoc_library(ctx):
    _check_non_empty(ctx.attr.root_packages, "root_packages")

    transitive_deps = [dep[JavaInfo].transitive_compile_time_jars for dep in ctx.attr.deps]
    if ctx.attr._android_jar:
        transitive_deps.append(ctx.attr._android_jar.files)

    classpath = depset([], transitive = transitive_deps).to_list()

    include_packages = ":".join(ctx.attr.root_packages)
    javadoc_command = [
        "%s/bin/javadoc" % ctx.attr._jdk[java_common.JavaRuntimeInfo].java_home,
        "-sourcepath srcs",
        "-use",
        "-subpackages",
        include_packages,
        "-encoding UTF8",
        "-classpath",
        ":".join([jar.path for jar in classpath]),
        "-notimestamp",
        "-d tmp",
        "-Xdoclint:-missing",
        "-quiet",
    ]

    if ctx.attr.doctitle:
        javadoc_command.append('-doctitle "%s"' % ctx.attr.doctitle)

    if ctx.attr.exclude_packages:
        javadoc_command.append("-exclude %s" % ":".join(ctx.attr.exclude_packages))

    for link in ctx.attr.external_javadoc_links:
        javadoc_command.append("-linkoffline {0} {0}".format(link))

    if ctx.attr.bottom_text:
        javadoc_command.append("-bottom '%s'" % ctx.attr.bottom_text)

    srcs = depset(transitive = [src.files for src in ctx.attr.srcs]).to_list()
    prepare_srcs_command = "mkdir srcs && "
    path_prefixes = [x.replace(".", "/") for x in ctx.attr.root_packages]
    for path_prefix in path_prefixes:
        prepare_srcs_command = "mkdir -p srcs/%s && " % (path_prefix)

    for src in srcs:
        if src.path.endswith(".jar"):
            prepare_srcs_command += "unzip -qq -B %s -d srcs && " % src.path
        elif src.path.endswith(".java"):
            for path_prefix in path_prefixes:
                if path_prefix in src.path:
                    prepare_srcs_command += "cp %s srcs/%s && " % (src.path, path_prefix)

    jar_binary = "%s/bin/jar" % ctx.attr._jdk[java_common.JavaRuntimeInfo].java_home
    jar_command = "%s cf %s -C tmp ." % (jar_binary, ctx.outputs.jar.path)

    ctx.actions.run_shell(
        inputs = srcs + classpath + ctx.files._jdk,
        command = "%s %s && %s" % (prepare_srcs_command, " ".join(javadoc_command), jar_command),
        outputs = [ctx.outputs.jar],
    )

javadoc_library = rule(
    attrs = {
        "srcs": attr.label_list(allow_files = True),
        "deps": attr.label_list(),
        "doctitle": attr.string(default = ""),
        "root_packages": attr.string_list(),
        "exclude_packages": attr.string_list(),
        "android_api_level": attr.int(default = -1),
        "bottom_text": attr.string(default = ""),
        "external_javadoc_links": attr.string_list(),
        "_android_jar": attr.label(
            default = _android_jar,
            allow_single_file = True,
        ),
        "_jdk": attr.label(
            default = Label("@bazel_tools//tools/jdk:current_java_runtime"),
            allow_files = True,
            providers = [java_common.JavaRuntimeInfo],
        ),
    },
    outputs = {"jar": "%{name}.jar"},
    implementation = _javadoc_library,
)
