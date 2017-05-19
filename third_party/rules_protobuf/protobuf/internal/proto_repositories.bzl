load("//third_party/rules_protobuf/protobuf:internal/require.bzl", "require")

def proto_repositories(excludes = [],
                       lang_deps = {},
                       lang_requires = [],
                       protobuf_deps = {},
                       protobuf_requires = [],
                       overrides = {},
                       verbose = 0):
  return require(
    keys = protobuf_requires + lang_requires,
    deps = protobuf_deps + lang_deps,
    excludes = excludes,
    overrides = overrides,
    verbose = verbose,
  )
