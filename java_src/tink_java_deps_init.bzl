"""Initialization of dependencies of Java Tink."""

load("@com_google_protobuf//:protobuf_deps.bzl", javalite_protobuf_deps = "protobuf_deps")
load("@build_bazel_rules_android//android:rules.bzl", "android_sdk_repository")

def tink_java_deps_init():
    """Initializes dependencies of Java Tink."""
    javalite_protobuf_deps()

    android_sdk_repository(
        name = "androidsdk",
        # Tink uses some APIs that only supported at this level.
        api_level = 26,  # Oreo
    )
