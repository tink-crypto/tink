licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//tools/build_defs:internal_pkg"])

load("//tools/build_defs:javac.bzl", "JAVACOPTS")

# keys downloader

java_library(
    name = "keysdownloader",
    srcs = [
        "KeysDownloader.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "@com_google_code_findbugs_jsr305",
        "@com_google_http_client//jar",
        "@joda_time//jar",
    ],
)
