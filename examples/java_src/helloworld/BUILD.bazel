load("@bazel_skylib//rules:build_test.bzl", "build_test")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

java_binary(
    name = "helloworld",
    srcs = glob([
        "src/main/**/*.java",
    ]),
    main_class = "com.helloworld.HelloWorld",
    runtime_deps = [
        "@com_google_protobuf//:protobuf_javalite",
        "@maven//:com_google_code_gson_gson",
    ],
    deps = [
        "@maven//:args4j_args4j",
        "@tink_java//src/main/java/com/google/crypto/tink:aead",
        "@tink_java//src/main/java/com/google/crypto/tink:cleartext_keyset_handle",
        "@tink_java//src/main/java/com/google/crypto/tink:json_keyset_reader",
        "@tink_java//src/main/java/com/google/crypto/tink:json_keyset_writer",
        "@tink_java//src/main/java/com/google/crypto/tink:key_templates",
        "@tink_java//src/main/java/com/google/crypto/tink:registry_cluster",
        "@tink_java//src/main/java/com/google/crypto/tink/aead:aead_config",
    ],
)

build_test(
    name = "helloworld_buildtest",
    targets = [":helloworld"],
)
