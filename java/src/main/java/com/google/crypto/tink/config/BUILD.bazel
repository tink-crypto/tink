licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//tools/build_defs:internal_pkg"])

load("//tools/build_defs:javac.bzl", "JAVACOPTS")

java_library(
    name = "config",
    srcs = [
        "TinkConfig.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink/daead",
        "//java/src/main/java/com/google/crypto/tink/hybrid",
        "//java/src/main/java/com/google/crypto/tink/signature",
        "//java/src/main/java/com/google/crypto/tink/streamingaead",
        "//proto:config_java_proto",
    ],
)

java_library(
    name = "android",
    srcs = [
        "TinkConfig.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink/daead:android",
        "//java/src/main/java/com/google/crypto/tink/hybrid:android",
        "//java/src/main/java/com/google/crypto/tink/signature:android",
        "//java/src/main/java/com/google/crypto/tink/streamingaead:android",
        "//proto:config_java_proto_lite",
    ],
)
