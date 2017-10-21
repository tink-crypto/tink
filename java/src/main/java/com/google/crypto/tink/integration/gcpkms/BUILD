licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//tools/build_defs:internal_pkg"])

load("//tools/build_defs:javac.bzl", "JAVACOPTS")

# public interfaces

java_library(
    name = "gcpkms",
    srcs = [
        "GcpKmsAead.java",
        "GcpKmsClient.java",
    ],
    javacopts = JAVACOPTS,
    plugins = [
        ":auto_service_plugin",
    ],
    deps = [
        "//java/src/main/java/com/google/crypto/tink",
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "@com_google_api_client//jar",
        "@com_google_auto_service//jar",
        "@com_google_cloudkms//jar",
        "@com_google_http_client//jar",
        "@com_google_http_client_jackson2//jar",
        "@com_google_oauth_client//jar",
    ],
)

java_plugin(
    name = "auto_service_plugin",
    processor_class = "com.google.auto.service.processor.AutoServiceProcessor",
    deps = [
        "@com_google_auto_common//jar",
        "@com_google_auto_service//jar",
        "@com_google_guava//jar",
    ],
)
