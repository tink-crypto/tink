package(default_visibility = ["//visibility:public"])

licenses(["notice"])  # Apache 2.0

load("//third_party/rules_protobuf/protobuf:rules.bzl", "proto_language", "proto_language_deps")

proto_language(
    name = "javalite",
    output_to_jar = True,
    pb_compile_deps = [
        "@com_google_protobuf_java//:protobuf_java",
    ],
    pb_file_extensions = [],
    pb_plugin = ":protoc_gen_javalite_bin",
    pb_runtime_deps = [],
)

genrule(
    name = "protoc_gen_javalite_bin",
    srcs = select({
        ":darwin": ["@protoc_gen_javalite_macosx//file"],
        "//conditions:default": ["@protoc_gen_javalite_linux_x86_64//file"],
    }),
    outs = ["protoc_gen_javalite"],
    cmd = " && ".join([
        "IN=$$(pwd)/$(SRCS)",
        "OUT=$$(pwd)/$@",
        "TMP=$$(mktemp -d $${TMPDIR:-/tmp}/genrule.XXXXXXXXXX)",
        "cd $$TMP",
        "cp $$IN $$OUT",
        "rm -rf $$TMP",
    ]),
    executable = True,
)

config_setting(
    name = "darwin",
    values = {"cpu": "darwin"},
    visibility = ["//visibility:private"],
)
