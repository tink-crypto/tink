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
        "//proto:java_common",
        "//proto:java_hmac",
        "//proto:java_tink",
        "//proto:java_tink_compile_imports",
    ],
)
