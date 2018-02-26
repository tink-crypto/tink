# Description:
#   Tink (https://github.com/google/tink) is a small crypto library that
#   provides a safe, simple, agile and fast way to accomplish some common
#   crypto tasks.

package(default_visibility = ["//tools/build_defs:internal_pkg"])

licenses(["notice"])  # Apache 2.0

exports_files(["LICENSE"])

# All go packages use github.com/google/tink prefix
load("@io_bazel_rules_go//go:def.bzl", "gazelle")

# bazel rule definition
gazelle(
    name = "gazelle",
    command = "update",
    prefix = "github.com/google/tink",
)

