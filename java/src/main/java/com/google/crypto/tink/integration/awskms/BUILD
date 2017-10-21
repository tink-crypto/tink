licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//tools/build_defs:internal_pkg"])

load("//tools/build_defs:javac.bzl", "JAVACOPTS")

# public interfaces

java_library(
    name = "awskms",
    srcs = glob([
        "*.java",
    ]),
    javacopts = JAVACOPTS,
    plugins = [
        ":auto_service_plugin",
    ],
    runtime_deps = [
        "@com_fasterxml_jackson_annotations//jar",
        "@com_fasterxml_jackson_databind//jar",
        "@com_google_code_gson_gson//jar",
        "@joda_time//jar",
        "@org_apache_commons_logging//jar",
        "@org_apache_httpcomponents_httpclient//jar",
        "@org_apache_httpcomponents_httpcore//jar",
    ],
    deps = [
        "//java/src/main/java/com/google/crypto/tink",
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "@com_amazonaws_sdk_core//jar",
        "@com_amazonaws_sdk_kms//jar",
        "@com_google_auto_service//jar",
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
