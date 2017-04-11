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
    name = "signature_srcs",
    srcs = glob(
        [
            "*.java",
        ],
    ),
)

java_library(
    name = "signature",
    srcs = [":signature_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/cloud/crypto/tink",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle:signature",
        "//proto:java_common",
        "//proto:java_ecdsa",
        "//proto:java_tink",
        "//proto:java_tink_compile_imports",
    ],
)
