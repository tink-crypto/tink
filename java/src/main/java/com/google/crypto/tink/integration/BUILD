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
        "AwsKmsClient.java",
        "GcpKmsAead.java",
        "GcpKmsClient.java",
        "IntegrationUtil.java",
    ]),
    javacopts = JAVACOPTS,
    plugins = [
        ":auto_service_plugin",
    ],
    runtime_deps = [
        "@com_fasterxml_jackson_annotations//jar",
        "@com_fasterxml_jackson_databind//jar",
        "@org_apache_commons_logging//jar",
        "@org_apache_httpcomponents_httpclient//jar",
        "@org_apache_httpcomponents_httpcore//jar",
    ],
    deps = [
        "//java/src/main/java/com/google/crypto/tink",
        "@com_amazonaws_sdk_core//jar",
        "@com_amazonaws_sdk_kms//jar",
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
