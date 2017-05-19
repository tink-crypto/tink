load("//third_party/rules_protobuf/javalite:deps.bzl", "DEPS")

load("//third_party/rules_protobuf/protobuf:rules.bzl",
     "proto_compile",
     "proto_language",
     "proto_language_deps",
     "proto_repositories")

def javalite_proto_repositories(
    lang_deps = DEPS,
    lang_requires = [
      "protoc_gen_javalite_linux_x86_64",
      "protoc_gen_javalite_macosx",
    ],
    **kwargs):

  proto_repositories(lang_deps = lang_deps,
                     lang_requires = lang_requires,
                     **kwargs)

def java_lite_proto_library(
    name,
    langs = [str(Label("//third_party/rules_protobuf/javalite:javalite"))],
    protos = [],
    imports = [],
    inputs = [],
    output_to_workspace = False,
    proto_deps = [],
    protoc = None,

    pb_plugin = None,
    pb_options = [],

    proto_compile_args = {},
    srcs = [],
    deps = [],
    verbose = 0,
    **kwargs):

  proto_compile_args += {
    "name": name + ".pb",
    "protos": protos,
    "deps": [dep + ".pb" for dep in proto_deps],
    "langs": langs,
    "imports": imports,
    "inputs": inputs,
    "pb_options": pb_options,
    "output_to_workspace": output_to_workspace,
    "verbose": verbose,
  }

  if protoc:
    proto_compile_args["protoc"] = protoc
  if pb_plugin:
    proto_compile_args["pb_plugin"] = pb_plugin

  proto_compile(**proto_compile_args)

  proto_language_deps(
    name = name + "_compile_deps",
    langs = langs,
    file_extensions = [".jar"],
  )

  native.java_import(
    name = name + "_compile_imports",
    jars = [name + "_compile_deps"],
  )

  java_exports = []

  native.java_library(
    name = name,
    srcs = srcs + [name + ".pb"],
    javacopts = ['-extra_checks:off'], # need this to disable ErrorProne.
    exports = java_exports,
    deps = list(set(deps + proto_deps + [name + "_compile_imports"])),
    **kwargs)
