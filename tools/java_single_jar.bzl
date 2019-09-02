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

def _check_non_empty(value, name):
    if not value:
        fail("%s must be non-empty" % name)

def _java_single_jar(ctx):
    _check_non_empty(ctx.attr.root_packages, "root_packages")

    inputs = depset()
    source_jars = []
    for dep in ctx.attr.deps:
        inputs = depset(transitive = [inputs, dep[JavaInfo].transitive_runtime_deps])
        source_jars += dep[JavaInfo].source_jars

    compress = ""
    if ctx.attr.compress == "preserve":
        compress = "--dont_change_compression"
    elif ctx.attr.compress == "yes":
        compress = "--compression"
    elif ctx.attr.compress == "no":
        pass
    else:
        fail("\"compress\" attribute (%s) must be: yes, no, preserve." % ctx.attr.compress)

    if ctx.attr.source_jar:
        inputs = depset(direct = source_jars)
        compress = ""

    args = ctx.actions.args()
    args.add("--sources")
    args.add_all(inputs)
    args.use_param_file(
        "@%s",
        use_always = True,
    )
    args.set_param_file_format("multiline")

    include_prefixes = " ".join([x.replace(".", "/") for x in ctx.attr.root_packages])

    ctx.actions.run(
        inputs = inputs,
        outputs = [ctx.outputs.jar],
        arguments = [
                        args,
                        "--output",
                        ctx.outputs.jar.path,
                        "--include_prefixes",
                        include_prefixes,
                        "--normalize",
                    ] +
                    # Deal with limitation of singlejar flags: tool's default behavior is
                    # "no", but you get that behavior only by absence of compression flags.
                    ([] if not compress else [compress]),
        progress_message = "Merging into %s" % ctx.outputs.jar.short_path,
        mnemonic = "JavaSingleJar",
        executable = ctx.executable._singlejar,
    )

java_single_jar = rule(
    attrs = {
        "deps": attr.label_list(providers = [JavaInfo]),
        "_singlejar": attr.label(
            default = Label("@bazel_tools//tools/jdk:singlejar"),
            cfg = "host",
            allow_single_file = True,
            executable = True,
        ),
        "source_jar": attr.bool(default = False),
        "compress": attr.string(default = "preserve"),
        "root_packages": attr.string_list(),
    },
    outputs = {
        "jar": "%{name}.jar",
    },
    implementation = _java_single_jar,
)
"""
Collects Java dependencies and jar files into a single jar

Args:
  deps: The Java targets (including java_import and java_library) to collect
      transitive dependencies from. Both compile-time dependencies (deps,
      exports) and runtime dependencies (runtime_deps) are collected.
      Resources are also collected. Native cc_library or java_wrap_cc
      dependencies are not.
  compress: Whether to always deflate ("yes"), always store ("no"), or pass
      through unmodified ("preserve"). The default is "preserve", and is the
      most efficient option -- no extra work is done to inflate or deflate.
  source_jar: Whether to combine the source jars of input to create a single
      output source jar.
  root_packages: Java packages to include in generated jar.

Outputs:
  {name}.jar: A single jar containing all of the input.
"""
