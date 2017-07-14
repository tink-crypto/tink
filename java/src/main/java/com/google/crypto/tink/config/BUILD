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
        "Config.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "tink_catalogue",
        "//java/src/main/java/com/google/crypto/tink",
        "//proto:config_java_proto",
    ],
)

java_library(
    name = "android",
    srcs = [
        "Config.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "tink_catalogue_android",
        "//java/src/main/java/com/google/crypto/tink",
        "//proto:config_java_proto_lite",
    ],
)

java_library(
    name = "tink_catalogue",
    srcs = [
        "Catalogue.java",
        "TinkCatalogue.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink",
        "//java/src/main/java/com/google/crypto/tink/aead",
        "//java/src/main/java/com/google/crypto/tink/hybrid",
        "//java/src/main/java/com/google/crypto/tink/mac",
        "//java/src/main/java/com/google/crypto/tink/signature",
        "//java/src/main/java/com/google/crypto/tink/streamingaead",
    ],
)

java_library(
    name = "tink_catalogue_android",
    srcs = [
        "Catalogue.java",
        "TinkCatalogue.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink:android",
        "//java/src/main/java/com/google/crypto/tink/aead:android",
        "//java/src/main/java/com/google/crypto/tink/hybrid:android",
        "//java/src/main/java/com/google/crypto/tink/mac:android",
        "//java/src/main/java/com/google/crypto/tink/signature:android",
        "//java/src/main/java/com/google/crypto/tink/streamingaead:android",
    ],
)
