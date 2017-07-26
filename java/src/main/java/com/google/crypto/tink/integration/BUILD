licenses(["notice"])  # Apache 2.0

package(
    default_visibility = [
        "//java:__subpackages__",
    ],
)

load("//java/build_defs:javac.bzl", "JAVACOPTS")

# public interfaces

java_library(
    name = "integration",
    srcs = glob([
        "AwsKmsAead.java",
        "CloudKmsClient.java",
        "GcpKmsAead.java",
        "GcpKmsClient.java",
        "GcpScopes.java",
        "IntegrationUtil.java",
    ]),
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink:primitives",
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "@com_amazonaws_sdk_core//jar",
        "@com_amazonaws_sdk_kms//jar",
        "@com_google_api_client//jar",
        "@com_google_cloudkms//jar",
        "@com_google_guava//jar",
        "@com_google_http_client//jar",
        "@com_google_http_client_jackson2//jar",
        "@com_google_oauth_client//jar",
    ],
)
