package(default_visibility = ["//visibility:public"])

licenses(["notice"])  # Apache 2.0

java_binary(
    name = "helloworld",
    srcs = glob([
        "src/main/**/*.java",
    ]),
    main_class = "com.helloworld.HelloWorld",
    runtime_deps = [
        "@com_google_protobuf_java//:protobuf_java",
        "@org_json_json//jar",
    ],
    deps = [
        "//java",
        "//java:cleartext_keyset_handle",
        "//java:subtle",
        "@args4j//jar",
    ],
)
