licenses(["notice"])  # Apache 2.0

package(
    default_visibility = [
        "//java:__subpackages__",
    ],
)

load("//java/build_defs:javac.bzl", "JAVACOPTS")

java_library(
    name = "config",
    srcs = [
        "TinkConfig.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink",
        "//java/src/main/java/com/google/crypto/tink/aead",
        "//java/src/main/java/com/google/crypto/tink/hybrid",
        "//java/src/main/java/com/google/crypto/tink/mac",
        "//java/src/main/java/com/google/crypto/tink/signature",
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
        "//java/src/main/java/com/google/crypto/tink:android",
        "//java/src/main/java/com/google/crypto/tink/aead:android",
        "//java/src/main/java/com/google/crypto/tink/hybrid:android",
        "//java/src/main/java/com/google/crypto/tink/mac:android",
        "//java/src/main/java/com/google/crypto/tink/signature:android",
        "//proto:config_java_proto_lite",
    ],
)
