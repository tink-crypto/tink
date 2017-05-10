licenses(["notice"])  # Apache 2.0

package(
    default_visibility = [
        "//java:__subpackages__",
    ],
)

JAVACOPTS = [
    "-Xlint:unchecked",
    "-Xlint:deprecation",
]

filegroup(
    name = "mac_srcs",
    srcs = glob(
        [
            "*.java",
        ],
    ),
)

java_library(
    name = "mac",
    srcs = [":mac_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/cloud/crypto/tink",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle:mac",
        "//proto:common_java_proto",
        "//proto:hmac_java_proto",
        "//proto:tink_java_proto",
        "//proto:tink_java_proto_compile_imports",
    ],
)
