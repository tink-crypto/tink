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
"""starlark rules for jarjar. See https://github.com/pantsbuild/jarjar
"""

load("@rules_java//java:defs.bzl", "JavaInfo")

def _jar_jar_impl(ctx):
    ctx.actions.run(
        inputs = [ctx.file.rules, ctx.file.input_jar],
        outputs = [ctx.outputs.jar],
        executable = ctx.executable._jarjar,
        progress_message = "jarjar %s" % ctx.label,
        arguments = ["process", ctx.file.rules.path, ctx.file.input_jar.path, ctx.outputs.jar.path],
    )

    return [
        JavaInfo(
            output_jar = ctx.outputs.jar,
            compile_jar = ctx.outputs.jar,
        ),
        DefaultInfo(files = depset([ctx.outputs.jar])),
    ]

jar_jar = rule(
    implementation = _jar_jar_impl,
    attrs = {
        "input_jar": attr.label(allow_single_file = True),
        "rules": attr.label(allow_single_file = True),
        "_jarjar": attr.label(executable = True, cfg = "exec", default = Label("//tools:jarjar")),
    },
    outputs = {
        "jar": "%{name}.jar",
    },
    provides = [JavaInfo],
)
