licenses(["notice"])  # Apache 2.0

package(
    default_visibility = [
        "//java:__subpackages__",
    ],
)

load("//java/build_defs:javac.bzl", "JAVACOPTS")

java_library(
    name = "annotations",
    srcs = glob([
        "*.java",
    ]),
    javacopts = JAVACOPTS,
)
