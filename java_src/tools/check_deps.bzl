# Copyright 2022 Google LLC
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

"""Defines a rule to check the dependencies of a given target."""

load("@bazel_skylib//lib:new_sets.bzl", "sets")

# Traverse the dependency graph along the "deps" attribute of the
# target and return a struct with one field called 'tf_collected_deps'.
# tf_collected_deps will be the union of the deps of the current target
# and the tf_collected_deps of the dependencies of this target.
# Borrowed from TensorFlow (https://github.com/tensorflow/tensorflow).
def _collect_deps_aspect_impl(target, ctx):
    direct, transitive = [], []
    all_deps = []
    if hasattr(ctx.rule.attr, "deps"):
        all_deps += ctx.rule.attr.deps
    if hasattr(ctx.rule.attr, "data"):
        all_deps += ctx.rule.attr.data
    for dep in all_deps:
        direct.append(dep.label)
        if hasattr(dep, "tf_collected_deps"):
            transitive.append(dep.tf_collected_deps)
    return struct(tf_collected_deps = depset(direct = direct, transitive = transitive))

collect_deps_aspect = aspect(
    attr_aspects = ["deps", "data"],
    implementation = _collect_deps_aspect_impl,
)

def _dep_label(dep):
    label = dep.label
    return label.package + ":" + label.name

# This rule checks that transitive dependencies don't depend on the targets
# listed in the 'disallowed_deps' attribute, but do depend on the targets listed
# in the 'required_deps' attribute. Dependencies considered are targets in the
# 'deps' attribute or the 'data' attribute.
# Borrowed from TensorFlow (https://github.com/tensorflow/tensorflow).
def _check_deps_impl(ctx):
    required_deps = ctx.attr.required_deps
    disallowed_deps = ctx.attr.disallowed_deps
    for input_dep in ctx.attr.deps:
        if not hasattr(input_dep, "tf_collected_deps"):
            continue
        collected_deps = sets.make(input_dep.tf_collected_deps.to_list())
        for disallowed_dep in disallowed_deps:
            if sets.contains(collected_deps, disallowed_dep.label):
                fail(
                    _dep_label(input_dep) + " cannot depend on " +
                    _dep_label(disallowed_dep),
                )
        for required_dep in required_deps:
            if not sets.contains(collected_deps, required_dep.label):
                fail(
                    _dep_label(input_dep) + " must depend on " +
                    _dep_label(required_dep),
                )

check_deps = rule(
    _check_deps_impl,
    attrs = {
        "deps": attr.label_list(
            aspects = [collect_deps_aspect],
            mandatory = True,
            allow_files = True,
        ),
        "disallowed_deps": attr.label_list(
            default = [],
            allow_files = True,
        ),
        "required_deps": attr.label_list(
            default = [],
            allow_files = True,
        ),
    },
)
