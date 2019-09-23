sh_binary(
    name = "pyclif",
    srcs = ["clif/bin/pyclif"],
    visibility = ["//visibility:public"],
)

sh_binary(
    name = "proto",
    srcs = ["clif/bin/pyclif_proto"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "cpp_runtime",
    srcs = glob(
        ["clif/python/*.cc"],
        exclude = ["clif/python/*_test.cc"],
    ),
    hdrs = glob(["clif/python/*.h"]),
    visibility = ["//visibility:public"],
    deps = [
        "@local_config_python//:python_headers",
        "@com_google_protobuf//:protobuf",
    ],
)
