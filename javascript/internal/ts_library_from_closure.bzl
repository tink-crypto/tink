"""Hacky way of allowing rules_nodejs targets to depend on rules_closure targets.

We don't have a way of producing TypeScript code directly from .proto schemas.
Nor do we have a way of managing their dependencies using ts_library. So what
we do is use closure_rules to generate code for the protos and to package up
all that code and its dependencies into a single .js file, add the required
ES exports and suppressions to that file, and feed it into the TypeScript
compiler.
"""

load("@bazel_skylib//rules:write_file.bzl", "write_file")
load("@io_bazel_rules_closure//closure:defs.bzl", "closure_js_binary", "closure_js_library")
load("@npm//@bazel/typescript:index.bzl", "ts_library")

def ts_library_from_closure(name, namespace_aliases, deps):
    """Returns a ts_library that wraps the given Closure libraries.

    Args:
      name: The name to give to the ts_library and its ES module.
      namespace_aliases: A dictionary whose keys are the names that this
        TypeScript ES module should export, and the values are the Closure
        namespaces whose values should be exported under those names.
      deps: The Closure libraries providing the above namespaces.
    """
    write_file(
        name = name + "_entry_point_js",
        out = name + "_entry_point.js",
        content = ["goog.module('epm${name}');".format(name = name)] + [
            "const epr${alias} = goog.require('{namespace}');".format(
                alias = alias,
                namespace = namespace,
            )
            for alias, namespace in namespace_aliases.items()
        ] + [
            "{alias} = epr${alias};".format(alias = alias)
            for alias in namespace_aliases
        ],
    )
    write_file(
        name = name + "_externs_js",
        out = name + "_externs.js",
        content = ["/** @externs */"] + [
            "let {alias};".format(alias = alias)
            for alias in namespace_aliases
        ],
    )
    closure_js_library(
        name = name + "_lib",
        srcs = [
            name + "_entry_point.js",
            name + "_externs.js",
        ],
        deps = deps,
    )
    closure_js_binary(
        name = name + "_bin",
        deps = [name + "_lib"],
        # ECMASCRIPT_NEXT is required since the subtle elliptic curve point
        # compression functions depend on BigInt, which was introduced in ES2020.
        # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt
        language = "ECMASCRIPT_NEXT",
        entry_points = ["epm${name}".format(name = name)],
        # Advanced optimizations remove dead code, which is a problem here
        # because we have no way to straightforwardly tell Closure Compiler
        # that the publicly-exposed properties of classes that are part of our
        # public API aren't dead code.
        compilation_level = "SIMPLE",
        # For easier debugging. Terser will remove this whitespace from
        # production builds.
        formatting = "PRETTY_PRINT",
    )
    write_file(
        name = name + "_preamble_js",
        out = name + "_preamble.js",
        content = ["// @ts-nocheck"] + [
            "export let {alias};".format(alias = alias)
            for alias in namespace_aliases
        ] + [
            "export type {alias} = any;".format(alias = alias)
            for alias in namespace_aliases
        ],
    )
    native.genrule(
        name = name + "_ts",
        srcs = [
            name + "_preamble.js",
            name + "_bin.js",
        ],
        outs = [name + ".ts"],
        cmd = "cat $(SRCS) >$@",
    )
    ts_library(
        name = name,
        srcs = [name + ".ts"],
    )
