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

""" Definition of java_single_jar. """

load("@rules_java//java:defs.bzl", "JavaInfo")

def _check_non_empty(value, name):
    if not value:
        fail("%s must be non-empty" % name)

def _java_single_jar(ctx):
    _check_non_empty(ctx.attr.root_packages, "root_packages")

    inputs = depset()
    if ctx.attr.source_jar:
        inputs = depset(transitive = [dep[JavaInfo].transitive_source_jars for dep in ctx.attr.deps])
    else:
        inputs = depset(transitive = [dep[JavaInfo].transitive_runtime_jars for dep in ctx.attr.deps])

    args = ctx.actions.args()
    args.add_all("--sources", inputs)
    args.use_param_file(
        "@%s",
        use_always = True,
    )
    args.set_param_file_format("multiline")
    args.add("--output", ctx.outputs.jar)
    args.add("--normalize")

    resource_files = depset(
        transitive = [resource.files for resource in ctx.attr.resources],
    ).to_list()
    args.add("--resources")
    for resource_file in resource_files:
        if not resource_file.path.startswith("src/main/resources"):
            fail("resource %s must be stored in src/main/resources/" % resource_file.path)
        relative_path = resource_file.path.replace("src/main/resources/", "")

        # Map src/main/resources/a/b/c.txt to a/b/c.txt.
        args.add(resource_file.path, format = "%s:" + relative_path)

    # Maybe compress code.
    if not ctx.attr.source_jar:
        # Deal with limitation of singlejar flags: tool's default behavior is
        # "no", but you get that behavior only by absence of compression flags.
        if ctx.attr.compress == "preserve":
            args.add("--dont_change_compression")
        elif ctx.attr.compress == "yes":
            args.add("--compression")
        elif ctx.attr.compress == "no":
            pass
        else:
            fail("\"compress\" attribute (%s) must be: yes, no, preserve." % ctx.attr.compress)

    # Each package prefix has to be specified in its own --include_prefixes arg.
    for p in ctx.attr.root_packages:
        args.add("--include_prefixes", p.replace(".", "/"))

    if ctx.attr.exclude_build_data:
        args.add("--exclude_build_data")

    args.add_all("--deploy_manifest_lines", ctx.attr.manifest_lines, format_each = "\"%s\"")

    ctx.actions.run(
        inputs = inputs.to_list() + resource_files,
        outputs = [ctx.outputs.jar],
        arguments = [args],
        progress_message = "Merging into %s" % ctx.outputs.jar.short_path,
        mnemonic = "JavaSingleJar",
        executable = ctx.executable._singlejar,
    )

java_single_jar = rule(
    attrs = {
        "deps": attr.label_list(providers = [JavaInfo]),
        "resources": attr.label_list(
            providers = [JavaInfo],
            allow_files = True,
        ),
        "_singlejar": attr.label(
            default = Label("@bazel_tools//tools/jdk:singlejar"),
            cfg = "exec",
            allow_single_file = True,
            executable = True,
        ),
        "source_jar": attr.bool(default = False),
        "compress": attr.string(default = "preserve"),
        "root_packages": attr.string_list(),
        "exclude_build_data": attr.bool(default = True),
        "manifest_lines": attr.string_list(),
    },
    outputs = {
        "jar": "%{name}.jar",
    },
    implementation = _java_single_jar,
    doc = """
Collects Java dependencies and jar files into a single jar

Args:
  deps: The Java targets (including java_import and java_library) to collect
      transitive dependencies from. Both compile-time dependencies (deps,
      exports) and runtime dependencies (runtime_deps) are collected.
      Resources are also collected. Native cc_library or java_wrap_cc
      dependencies are not.
  resources: A combination of resource files. Files must be stored in
      src/main/resources. Mapping rules: src/main/resources/a/b/c.txt will be
      copied to a/b/c.txt in the output jar.
  compress: Whether to always deflate ("yes"), always store ("no"), or pass
      through unmodified ("preserve"). The default is "preserve", and is the
      most efficient option -- no extra work is done to inflate or deflate.
  source_jar: Whether to combine only the source jars of input to create a single
      output source jar. The compiled code jars of input will be ignored.
  root_packages: Java packages to include in generated jar.
  exclude_build_data: Whether to omit the build-data.properties file generated
      by default.
  manifest_lines: lines to put in the output manifest file (manifest
      files in the input jars are ignored)

Outputs:
  {name}.jar: A single jar containing all of the input.
""",
)
